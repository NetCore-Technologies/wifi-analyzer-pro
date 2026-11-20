import { createContext, useContext } from 'react';

export const AuthContext = createContext({ logout: async () => {}, identity: null });

export function useAuth() {
  return useContext(AuthContext);
}
