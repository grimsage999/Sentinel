import React from 'react';

// Lazy load React Query DevTools only in development
const ReactQueryDevtools = React.lazy(() =>
  import('@tanstack/react-query-devtools').then((module) => ({
    default: module.ReactQueryDevtools,
  }))
);

export const DevTools: React.FC = () => {
  // Only show devtools in development
  if (import.meta.env.MODE === 'production') {
    return null;
  }

  return (
    <React.Suspense fallback={null}>
      <ReactQueryDevtools />
    </React.Suspense>
  );
};