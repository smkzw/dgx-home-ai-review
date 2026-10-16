"""Arithmetic illustration using published elapsed durations, never a proof."""
WHOLE30=30.0
FINISH_ELAPSED=14.378944276
ACTIVATION_ELAPSED=23.240539148

def accepted(begin,finish,activation_end):
    return begin<=finish<=activation_end and activation_end-begin<=WHOLE30

if __name__=='__main__':
    total=FINISH_ELAPSED+ACTIVATION_ELAPSED
    assert not accepted(0.0,FINISH_ELAPSED,total)
    assert not accepted(0.0,14.0,30.000001)
    print({'illustrative_total':total,'within_original_whole30':False,
           'not_a_native_replay':True})
