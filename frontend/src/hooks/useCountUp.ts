import { useState, useEffect, useRef } from 'react';

export function useCountUp(target: number, duration = 1200, delay = 0) {
  const [count, setCount] = useState(0);
  const frameRef = useRef<number>(0);

  useEffect(() => {
    const startTime = performance.now() + delay;
    let started = false;

    const animate = (now: number) => {
      if (!started) {
        if (now < startTime) {
          frameRef.current = requestAnimationFrame(animate);
          return;
        }
        started = true;
      }

      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.floor(eased * target));

      if (progress < 1) {
        frameRef.current = requestAnimationFrame(animate);
      } else {
        setCount(target);
      }
    };

    frameRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frameRef.current);
  }, [target, duration, delay]);

  return count;
}
