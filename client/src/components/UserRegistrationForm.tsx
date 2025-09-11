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

interface UserForm {
  username: string;
  email: string;
  password: string;
}

const UserRegistrationForm = () => {
  const [formData, setFormData] = useState<UserForm>({
    username: "",
    email: "",
    password: "",
  });

  const [status, setStatus] = useState<"success" | "error" | null>(null);
  const [message, setMessage] = useState<string>("");

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch("http://localhost:3000/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.message || `Error: ${res.status}`);
      }

      setStatus("success");
      setMessage("✅ Registration successful! You can now sign in.");
      setFormData({ username: "", email: "", password: "" });
    } catch (err: any) {
      console.error("Registration error:", err);
      setStatus("error");
      setMessage(err.message || "❌ Something went wrong. Please try again.");
    }
  };

  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  return (
    <Box minH="100vh" bg={useColorModeValue("gray.100", "gray.900")} py={12} px={4}>
      <Center>
        <Box
          w="full"
          maxW="2xl"
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
                Create Account
              </Heading>
              <Text color={useColorModeValue("gray.600", "gray.400")}>
                Join us today and get started
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

                <FormControl id="email" isRequired>
                  <FormLabel fontWeight="semibold">Email</FormLabel>
                  <Input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter email"
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
                >
                  Create Account
                </Button>
              </VStack>
            </form>

            <Text fontSize="sm" textAlign="center" color={useColorModeValue("gray.600", "gray.400")} mt={2}>
              Already have an account?{" "}
              <Link color="blue.500" fontWeight="semibold" href="#">
                Sign in
              </Link>
            </Text>
          </VStack>
        </Box>
      </Center>
    </Box>
  );
};

export default UserRegistrationForm;
