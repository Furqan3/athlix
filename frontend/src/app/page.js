
'use client';
import { useEffect } from 'react';

export default function RedirectToSignin() {
  useEffect(() => {
    window.location.href = '/signin';
  }, []);

  return <div>Redirecting...</div>;
}