# Concepts

An **execution intent** is the immutable, short-lived representation of exactly what an agent proposes. A **gate** asks an authority whether that intent is allowed. A **grant** is a signed, single-use capability bound to one allowed intent. A **safe executor** consumes that grant and invokes a pre-registered trusted handler.

`ALLOW` means Decionis issued an execution grant. `ESCALATE` means independent human evidence is required and must be returned to Decionis. `BLOCK` means no execution. Presence approval does not change those meanings; only Decionis can issue the final grant.

A **Decision Dossier** is evidence of the decision and inputs. It is not itself an execution credential.
