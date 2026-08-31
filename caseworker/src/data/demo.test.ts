import { describe, expect, it } from 'vitest'

import { freshDemoCase } from './demo'


describe('demo case', () => {
  it('returns an isolated copy at the human approval boundary', () => {
    const first = freshDemoCase()
    const second = freshDemoCase()

    expect(first.status).toBe('ready_for_approval')
    expect(first.current_action?.status).toBe('approval_required')
    expect(first.current_action?.evidence_ids).toEqual(['EV-01', 'EV-02', 'EV-04'])

    first.claims[0].statement = 'changed'
    expect(second.claims[0].statement).not.toBe('changed')
  })

  it('keeps every material claim linked to evidence', () => {
    const record = freshDemoCase()
    for (const claim of record.claims) {
      expect([...claim.supporting_evidence_ids, ...claim.contradicting_evidence_ids].length).toBeGreaterThan(0)
    }
  })
})
