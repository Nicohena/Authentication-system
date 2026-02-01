import { createContext, useState, useEffect } from "react";
import axios from "axios";
import { toast } from "react-toastify";

export const AppContext = createContext();

export const AppContextProvider = ({ children }) => {
    axios.defaults.withCredentials = true; // ensure cookies are sent

    const backendUrl = import.meta.env.VITE_BACKEND_URL;
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState(true); // NEW: wait for auth check

    // ✅ check auth on load
    const getAuthStatus = async () => {
        try {
            const { data } = await axios.get(`${backendUrl}/api/auth/is-auth`, {
                withCredentials: true
            });

            if (data.success) {
                setIsLoggedIn(true);
                setUserData(data.user); // NEW: set user data from backend
            } else {
                setIsLoggedIn(false);
                setUserData(null);
            }
        } catch (err) {
            setIsLoggedIn(false);
            setUserData(null);
        } finally {
            setLoading(false); // NEW: finished loading
        }
    };

    // ✅ get user data manually
    const getUserData = async () => {
        try {
            const { data } = await axios.get(`${backendUrl}/api/user/data`, { withCredentials: true });
            if (data.success) {
                setUserData(data.user);
            }
        } catch (err) {
            toast.error("Failed to fetch user data");
        }
    };

    // ✅ run auth check on mount
    useEffect(() => {
        getAuthStatus();
    }, []);

    const value = {
        backendUrl,
        isLoggedIn,
        setIsLoggedIn,
        userData,
        setUserData,
        getUserData,
        getAuthStatus,
        loading // NEW
    };

    return (
        <AppContext.Provider value={value}>
            {children}
        </AppContext.Provider>
    );
};
