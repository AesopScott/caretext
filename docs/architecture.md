# Care Text Architecture

## Inspiration Message Categories

Care Text uses message categories to choose random inspiration or hope messages with enough context to feel intentional. Categories should be distinct by message intent, not just mood words.

Most categories are direct-message categories: they are meant to speak into a specific care moment, relationship need, or emotional state. One category is intentionally non-direct so the system can send general inspiration without implying a specific event is happening.

### Categories

| Key | Name | Message mode | Use |
| --- | --- | --- | --- |
| `morning_start` | Morning Start | Direct | Encouragement for beginning the day. |
| `end_of_day_reflection` | End-of-Day Reflection | Direct | Gentle messages for closing the day. |
| `during_treatment` | During Treatment | Direct | Support while someone is actively in care or treatment. |
| `scan_or_test_anxiety` | Scan or Test Anxiety | Direct | Reassurance before tests, scans, lab work, or results. |
| `before_surgery_or_procedure` | Before Surgery or Procedure | Direct | Calm and courage before a medical procedure. |
| `recovery_milestones` | Recovery Milestones | Direct | Recognition of progress, healing, and next steps. |
| `pain_or_fatigue_days` | Pain or Fatigue Days | Direct | Support for physically difficult days. |
| `feeling_isolated` | Feeling Isolated | Direct | Reminders of presence, connection, and being remembered. |
| `family_and_caregiver_support` | Family and Caregiver Support | Direct | Encouragement for caregivers and family members. |
| `faith_based_hope` | Faith-Based Hope | Direct | Spiritually grounded messages for recipients who welcome faith language. |
| `nonreligious_hope` | Nonreligious Hope | Direct | Hopeful messages without religious or spiritual framing. |
| `grief_and_loss` | Grief and Loss | Direct | Tender support around loss, sadness, or mourning. |
| `uncertainty_about_the_future` | Uncertainty About the Future | Direct | Steadiness when the path ahead is unclear. |
| `celebrating_small_wins` | Celebrating Small Wins | Direct | Recognition of small victories and meaningful progress. |
| `self_compassion` | Self-Compassion | Direct | Permission to be gentle with oneself. |
| `practical_grounding` | Practical Grounding | Direct | Short, calming prompts for breath, attention, and the present moment. |
| `hard_conversations` | Hard Conversations | Direct | Courage and care around difficult talks. |
| `long_haul_perseverance` | Long-Haul Perseverance | Direct | Encouragement for ongoing, slow, or tiring seasons. |
| `community_and_belonging` | Community and Belonging | Direct | Reminders that care can come from a wider circle. |
| `everyday_beauty` | Everyday Beauty | Non-direct | Ambient inspiration from ordinary life, nature, seasons, music, light, gratitude, and small moments of goodness. |

### Selection Notes

- Direct categories should only be used when the recipient context makes the category appropriate.
- `everyday_beauty` is safe for random inspiration when there is no known care event or emotional context.
- Faith-based and nonreligious categories should respect recipient preference and should not be mixed by default.
- Category copy should avoid diagnosing the recipient's state unless the system has explicit context for that category.
