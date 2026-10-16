"""Pure local math. No deployment imports, files, credentials or RPC."""
import math

def check(origin,duration=120.0):
    deadline=origin+duration
    return {'subtract_equal':deadline-origin==duration,
            'producer_exact_equal':deadline==origin+duration,
            'nextafter_plus_rejected':math.nextafter(deadline,math.inf)!=origin+duration,
            'nextafter_minus_rejected':math.nextafter(deadline,-math.inf)!=origin+duration}

if __name__=='__main__':
    for value in (100.0,65535.99999999999,2**30+0.123456789):
        result=check(value)
        assert result['producer_exact_equal']
        assert result['nextafter_plus_rejected'] and result['nextafter_minus_rejected']
        print(result)
