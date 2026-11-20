import { createContext, useContext } from 'react';

export const AuthContext = createContext({ logout: async () => {} });

export function useAuth() {
  return useContext(AuthContext);
}
