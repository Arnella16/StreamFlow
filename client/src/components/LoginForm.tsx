import {
  Box,
  Button,
  Input,
  Heading,
  Text,
  VStack,
  Link,
  Center,
  useColorModeValue,
  FormControl,
  FormLabel,
} from "@chakra-ui/react";
import { useState } from "react";
import type { ChangeEvent, FormEvent } from "react";

interface LoginForm {
  username: string;
  password: string;
}

interface LoginFormProps {
  onLogin: (userData: any) => void;
  onSwitchToRegister: () => void;
}

const LoginForm = ({ onLogin, onSwitchToRegister }: LoginFormProps) => {
  const [formData, setFormData] = useState<LoginForm>({
    username: "",
    password: "",
  });

  const [status, setStatus] = useState<"success" | "error" | null>(null);
  const [message, setMessage] = useState<string>("");
  const [loading, setLoading] = useState(false);

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch("http://98.70.25.253:3000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || `Error: ${res.status}`);
      }

      // Store the token in localStorage
      if (data.token) {
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('user_info', JSON.stringify(data.user));
      }

      setStatus("success");
      setMessage("✅ Login successful!");
      setFormData({ username: "", password: "" });
      
      // Call the onLogin callback with user data
      onLogin(data.user);

    } catch (err: any) {
      console.error("Login error:", err);
      setStatus("error");
      setMessage(err.message || "❌ Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  return (
    <Box minH="100vh" bg={useColorModeValue("gray.100", "gray.900")} pt="80px" px={4}>
      <Center>
        <Box
          w="full"
          maxW="md"
          bg={cardBg}
          boxShadow="2xl"
          borderRadius="xl"
          borderWidth="1px"
          borderColor={borderColor}
          p={10}
        >
          <VStack gap={6} align="stretch">
            <Box textAlign="center">
              <Heading size="lg" mb={2} color={useColorModeValue("blue.600", "blue.300")}>
                Sign In
              </Heading>
              <Text color={useColorModeValue("gray.600", "gray.400")}>
                Welcome back to StreamFlow
              </Text>
            </Box>

            {status && (
              <Text
                color={status === "success" ? "green.500" : "red.500"}
                fontSize="sm"
                textAlign="center"
              >
                {message}
              </Text>
            )}

            <form onSubmit={handleSubmit}>
              <VStack gap={5} align="stretch">
                <FormControl id="username" isRequired>
                  <FormLabel fontWeight="semibold">Username</FormLabel>
                  <Input
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                    placeholder="Enter username"
                    size="lg"
                  />
                </FormControl>

                <FormControl id="password" isRequired>
                  <FormLabel fontWeight="semibold">Password</FormLabel>
                  <Input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="Enter password"
                    size="lg"
                  />
                </FormControl>

                <Button
                  type="submit"
                  colorScheme="blue"
                  size="lg"
                  fontWeight="bold"
                  w="full"
                  mt={2}
                  isLoading={loading}
                  loadingText="Signing in..."
                >
                  Sign In
                </Button>
              </VStack>
            </form>

            <Text fontSize="sm" textAlign="center" color={useColorModeValue("gray.600", "gray.400")} mt={2}>
              Don't have an account?{" "}
              <Link color="blue.500" fontWeight="semibold" onClick={onSwitchToRegister} cursor="pointer">
                Create Account
              </Link>
            </Text>
          </VStack>
        </Box>
      </Center>
    </Box>
  );
};

export default LoginForm;
