import { Flex, Box, IconButton, Text, useColorMode } from "@chakra-ui/react";
import { SunIcon, MoonIcon } from "@chakra-ui/icons";

const Navbar = () => {
  const { colorMode, toggleColorMode } = useColorMode();

  return (
    <Flex
      as="nav"
      position="fixed"
      top={0}
      left={0}
      right={0}
      zIndex={100}
      align="center"
      justify="space-between"
      px={6}
      h="64px"
      bg={colorMode === "light" ? "white" : "gray.800"}
      boxShadow="sm"
    >
      {/* Logo */}
      <Box>
        <Text fontWeight="bold" fontSize="xl" color="blue.500">
          StreamFlow
        </Text>
      </Box>

      {/* Theme Toggle */}
      <IconButton
        aria-label="Toggle dark mode"
        onClick={toggleColorMode}
        variant="ghost"
        size="lg"
        icon={colorMode === "light" ? <MoonIcon /> : <SunIcon />}
      />
    </Flex>
  );
};

export default Navbar;