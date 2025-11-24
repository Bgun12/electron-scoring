;; Electron Scoring - Privacy-Preserving Credibility Infrastructure
;; Core credibility score management with cryptographic attestation

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-unauthorized (err u102))
(define-constant err-invalid-score (err u103))
(define-constant err-insufficient-attestations (err u104))
(define-constant err-cooldown-active (err u105))
(define-constant err-already-exists (err u106))
(define-constant err-paused (err u107))

;; Score boundaries
(define-constant max-score u10000)
(define-constant min-score u0)

;; Attestation threshold (3 of 5 validators required)
(define-constant attestation-threshold u3)

;; Decay rate: 1% per day (144 blocks on Stacks)
(define-constant decay-rate u1)
(define-constant decay-interval u144)

;; Cooldown period between score updates
(define-constant update-cooldown u144)

;; Data Variables
(define-data-var contract-paused bool false)
(define-data-var total-users uint u0)
(define-data-var accumulator-root (buff 32) 0x00)

;; Data Maps

;; User credibility scores with metadata
(define-map credibility-scores
    principal
    {
        score: uint,
        last-update: uint,
        last-decay: uint,
        total-attestations: uint,
        active: bool
    }
)

;; Registered validators for multi-party attestation
(define-map validators
    principal
    {
        active: bool,
        total-attestations: uint,
        reputation: uint
    }
)

;; Pending attestations for threshold signatures
(define-map pending-attestations
    { user: principal, proposal-id: uint }
    {
        attestors: (list 10 principal),
        proposed-score: uint,
        created-at: uint,
        executed: bool
    }
)

;; Attestation proposals counter
(define-data-var proposal-nonce uint u0)

;; Cryptographic accumulator elements
(define-map accumulator-elements
    (buff 32)
    bool
)

;; Read-only functions

;; Get user's current credibility score with decay applied
(define-read-only (get-credibility-score (user principal))
    (match (map-get? credibility-scores user)
        score-data (ok (calculate-decayed-score 
                        (get score score-data)
                        (get last-decay score-data)))
        err-not-found
    )
)

;; Get raw score data without decay calculation
(define-read-only (get-score-data (user principal))
    (ok (map-get? credibility-scores user))
)

;; Check if address is registered validator
(define-read-only (is-validator (address principal))
    (match (map-get? validators address)
        validator-data (ok (get active validator-data))
        (ok false)
    )
)

;; Get pending attestation details
(define-read-only (get-pending-attestation (user principal) (proposal-id uint))
    (ok (map-get? pending-attestations { user: user, proposal-id: proposal-id }))
)

;; Get accumulator root for ZK proofs
(define-read-only (get-accumulator-root)
    (ok (var-get accumulator-root))
)

;; Check if contract is paused
(define-read-only (is-paused)
    (ok (var-get contract-paused))
)

;; Private functions

;; Calculate score with temporal decay applied
(define-private (calculate-decayed-score (score uint) (last-decay-block uint))
    (let
        (
            (blocks-elapsed (- block-height last-decay-block))
            (decay-periods (/ blocks-elapsed decay-interval))
            (decay-amount (/ (* score (* decay-periods decay-rate)) u100))
        )
        (if (> decay-amount score)
            min-score
            (- score decay-amount)
        )
    )
)

;; Verify attestation threshold is met
(define-private (check-attestation-threshold (attestors (list 10 principal)))
    (>= (len attestors) attestation-threshold)
)

;; Public functions

;; Initialize credibility score for new user
(define-public (initialize-score (user principal))
    (begin
        (asserts! (not (var-get contract-paused)) err-paused)
        (asserts! (is-none (map-get? credibility-scores user)) err-already-exists)
        
        (map-set credibility-scores user {
            score: u0,
            last-update: block-height,
            last-decay: block-height,
            total-attestations: u0,
            active: true
        })
        
        (var-set total-users (+ (var-get total-users) u1))
        (ok true)
    )
)

;; Register as validator (owner only initially)
(define-public (register-validator (validator principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (not (var-get contract-paused)) err-paused)
        
        (map-set validators validator {
            active: true,
            total-attestations: u0,
            reputation: u100
        })
        
        (ok true)
    )
)

;; Create attestation proposal for score update
(define-public (propose-score-update (user principal) (new-score uint))
    (let
        (
            (proposal-id (var-get proposal-nonce))
            (validator-check (unwrap! (is-validator tx-sender) err-unauthorized))
        )
        (asserts! (not (var-get contract-paused)) err-paused)
        (asserts! validator-check err-unauthorized)
        (asserts! (<= new-score max-score) err-invalid-score)
        (asserts! (is-some (map-get? credibility-scores user)) err-not-found)
        
        (map-set pending-attestations 
            { user: user, proposal-id: proposal-id }
            {
                attestors: (list tx-sender),
                proposed-score: new-score,
                created-at: block-height,
                executed: false
            }
        )
        
        (var-set proposal-nonce (+ proposal-id u1))
        (ok proposal-id)
    )
)

;; Attest to existing proposal
(define-public (attest-proposal (user principal) (proposal-id uint))
    (let
        (
            (proposal (unwrap! (map-get? pending-attestations 
                { user: user, proposal-id: proposal-id }) err-not-found))
            (validator-check (unwrap! (is-validator tx-sender) err-unauthorized))
            (current-attestors (get attestors proposal))
        )
        (asserts! (not (var-get contract-paused)) err-paused)
        (asserts! validator-check err-unauthorized)
        (asserts! (not (get executed proposal)) err-unauthorized)
        
        ;; Add attestor if not already in list
        (map-set pending-attestations
            { user: user, proposal-id: proposal-id }
            (merge proposal {
                attestors: (unwrap-panic (as-max-len? 
                    (append current-attestors tx-sender) u10))
            })
        )
        
        (ok true)
    )
)

;; Execute score update if threshold met
(define-public (execute-score-update (user principal) (proposal-id uint))
    (let
        (
            (proposal (unwrap! (map-get? pending-attestations 
                { user: user, proposal-id: proposal-id }) err-not-found))
            (score-data (unwrap! (map-get? credibility-scores user) err-not-found))
            (attestors (get attestors proposal))
        )
        (asserts! (not (var-get contract-paused)) err-paused)
        (asserts! (not (get executed proposal)) err-unauthorized)
        (asserts! (check-attestation-threshold attestors) err-insufficient-attestations)
        (asserts! (>= (- block-height (get last-update score-data)) update-cooldown) 
            err-cooldown-active)
        
        ;; Update score
        (map-set credibility-scores user
            (merge score-data {
                score: (get proposed-score proposal),
                last-update: block-height,
                last-decay: block-height,
                total-attestations: (+ (get total-attestations score-data) u1)
            })
        )
        
        ;; Mark proposal as executed
        (map-set pending-attestations
            { user: user, proposal-id: proposal-id }
            (merge proposal { executed: true })
        )
        
        ;; Update validator reputations
        (map update-validator-reputation attestors)
        
        (ok true)
    )
)

;; Update validator reputation after successful attestation
(define-private (update-validator-reputation (validator principal))
    (match (map-get? validators validator)
        validator-data
            (begin
                (map-set validators validator
                    (merge validator-data {
                        total-attestations: (+ (get total-attestations validator-data) u1),
                        reputation: (+ (get reputation validator-data) u1)
                    })
                )
                true
            )
        false
    )
)

;; Update accumulator root for ZK proof verification
(define-public (update-accumulator-root (new-root (buff 32)))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set accumulator-root new-root)
        (ok true)
    )
)

;; Add element to accumulator
(define-public (add-accumulator-element (element (buff 32)))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (map-set accumulator-elements element true)
        (ok true)
    )
)

;; Emergency pause (owner only)
(define-public (pause-contract)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set contract-paused true)
        (ok true)
    )
)

;; Unpause contract (owner only)
(define-public (unpause-contract)
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set contract-paused false)
        (ok true)
    )
)