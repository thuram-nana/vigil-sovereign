# Consumer withdrawal (the 14-day right, Terms §8)

How the owner carries out a consumer's withdrawal from a credit pack or a monthly plan: refund the money in
Stripe, stop a plan's renewal, and remove the purchase's credits from VIGIL. Terms §8 gives a consumer who
lives where the law grants a right of withdrawal (the European Union, the European Economic Area, the United
Kingdom) 14 days to withdraw from a purchase, and promises the refund **within 14 days of receiving the
withdrawal**. Do every step below inside that time.

The Terms say what is refunded: the price of the purchase's credits the customer has **not used**, in
proportion. Once every credit of a purchase is used, its right of withdrawal has ended. For a plan, the 14 days
run from its first purchase, and a plan the customer withdraws from does not renew.

## Before the first withdrawal (once)

- `VIGIL_BILLING_REVERSALS=1` in the Stripe drain's env (`~/.config/vigil/billing-drain-stripe.env`) and in the
  env of the shell that runs `sigil billing-reversal` (the cockpit env carries the line). Both examples ship it
  commented out; every `billing-reversal` verb refuses while it is off.
- The Stripe webhook endpoint (GO-LIVE §9b step 1) also sends the refund events the drain acts on:
  `charge.refunded`, `charge.refund.updated`, `refund.created`, `refund.updated`, `refund.failed` (and the
  `charge.dispute.*` events for chargebacks).
- The restricted Stripe key can read Charges, Refunds, Disputes, Invoices and Subscriptions. For VIGIL to stop a
  plan's renewal itself it also needs write access to Subscriptions; without it, cancel the subscription in the
  Stripe Dashboard (step P4) and the verb only confirms it.
- The shell that runs `plan-withdraw` has the cockpit's `SIGIL_HOME`, `VIGIL_STRIPE_SECRET_KEY` and
  `VIGIL_STRIPE_API_VERSION`. Without the Stripe values the verb cannot confirm the renewal is stopped, so it
  refuses and prints the Stripe step instead.

## The rule for "the credits you have not used"

- **A plan period:** the plan credits that remain in that period. Plan credits are spent first, so this is the
  part of the allotment the customer did not use.
- **A credit pack:** the wallet keeps one balance for trial and bought credits, so VIGIL cannot see which pack a
  spent credit came from. VIGIL uses the reading that favours the customer:
  - trial credits count as spent **first** and never count as purchased;
  - **purchased balance remaining** = the smaller of the wallet balance and the credits bought (less what
    refunds already removed);
  - **unused credits of the pack** = the smaller of that pack's credits (less what a refund already removed from
    it) and the purchased balance remaining.

  Example: 450 trial credits, one 1,000-credit pack ($10), 600 credits used. The balance is 850, the purchased
  balance remaining is 850 (the 450 trial credits were spent first), so 850 credits of the pack are unused and
  the refund is $8.50.
- **The refund** is the purchase's price in proportion to its unused credits, rounded up to the cent.

`sigil billing-reversal unused <org> <purchase>` prints the unused credits, the purchased balance remaining (for
a pack) and the refund, and the verb to run next. It writes nothing. The purchase is the billing-history id: a
pack's Stripe Checkout Session id (`cs_...`), a plan period's Stripe invoice id (`in_...`).

## A credit pack

1. Check the request: the customer is a consumer and wrote within 14 days of the purchase. Note the date you
   received it.
2. `sigil billing-reversal unused <org> <cs_...>` — note the unused credits `N` and the refund `R`. When it says
   every credit is used, the right of withdrawal has ended: tell the customer, nothing else to do.
3. In the Stripe Dashboard open the payment and refund `R` to the original payment method.
4. `sigil billing-reversal refund <org> <cs_...> <N> --reason "withdrawal received <date>"` — removes the `N`
   unused credits (refused if the balance no longer covers them: run step 2 again). Run it once per refund: each
   run adds to the refunded credits. The drain also removes credits when Stripe's refund event arrives; the two
   converge on one removal, whichever comes first.

## A monthly plan

1. Check the request: the customer is a consumer and wrote within 14 days of the plan's first purchase. Note the
   date you received it.
2. Find the plan period's invoice id (`in_...`): the subscription's first invoice in Stripe, which is also the
   id of the period's line in the org's billing history.
3. `sigil billing-reversal unused <org> <in_...>` — note the unused plan credits and the refund `R`.
4. In the Stripe Dashboard refund `R` on the invoice's payment, to the original payment method. If you prefer,
   also open the subscription and choose **Cancel subscription** now; otherwise step 5 stops the renewal.
5. `sigil billing-reversal plan-withdraw <org> <in_...> <R> --reason "withdrawal received <date>"`, where `R` is
   the **total** refunded at Stripe for that invoice, in cents. It first stops the renewal: a subscription that
   is already cancelled, or already set to end at the end of its period, is left as it is; otherwise VIGIL sets
   it to end at the end of the period, checks Stripe's answer and reads the subscription back to confirm it.
   Each run sends its own update, so a plan the customer resumed after an earlier run is stopped again. When
   VIGIL cannot do that (no Stripe key in the shell, a key without write access, an unconfirmed answer or
   read-back), it refuses, removes nothing and prints the
   Stripe step: open the subscription in the Dashboard, choose **Cancel subscription**, then run the command
   again. Once the renewal is stopped it removes the plan credits for `R` (the allotment in the refunded
   proportion), never more than remain in the period. Running it again with the same `R` removes nothing more
   (only credits that came back to the period since, for example from a refunded scan).

## What the drain does on its own

With `VIGIL_BILLING_REVERSALS` on, the Stripe drain re-fetches every refund from Stripe:

- a refund of a credit pack removes that pack's credits in the refunded proportion; a part already spent is
  owed and puts the org on a billing hold until a later purchase repays it;
- a refund of a plan payment is traced from the charge to its invoice and to the subscription that names the
  org, and removes that period's plan credits in the refunded proportion, from what remains (a spent part is
  never owed);
- a refund VIGIL cannot trace to one credited purchase (a disputed plan payment, a monitoring plan, an unknown
  charge) is quarantined for you to reconcile by hand. A refund never adds credits: if a plan refund later goes
  down (a failed refund), the drain quarantines it and the removed plan credits are not given back.

## Keep a record

For each withdrawal keep the date you received it, the Stripe refund id and amount, and the output of the
VIGIL verb (it names the owner-signed step's spine seq). Refunds and withdrawals do not change a report unlock:
relock with `sigil org relock-reports <org> --reason ...` only if you decide to.
