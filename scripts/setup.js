const fs = require("fs")
const path = require("path")
const { execSync } = require("child_process")
const inquirer = require("inquirer")

console.log("🚀 Expense Tracker Interactive Setup")
console.log("====================================\n")

async function main() {
  try {
    // Check system requirements
    console.log("📋 Checking system requirements...")
    checkRequirements()

    // Get user configuration
    const config = await getUserConfig()

    // Create project structure
    console.log("\n📁 Creating project structure...")
    createProjectStructure()

    // Setup frontend
    console.log("\n🎨 Setting up frontend...")
    setupFrontend()

    // Setup backend
    console.log("\n🐍 Setting up backend...")
    setupBackend()

    // Create configuration files
    console.log("\n🔧 Creating configuration files...")
    createConfigFiles(config)

    // Setup database
    console.log("\n🗄️  Setting up database...")
    setupDatabase(config)

    console.log("\n✅ Setup completed successfully! 🎉")
    console.log("\n📋 Next Steps:")
    console.log("1. Start backend: cd backend && python app.py")
    console.log("2. Start frontend: cd frontend && npm run dev (in new terminal)")
    console.log("3. Open http://localhost:3000 in your browser")
  } catch (error) {
    console.error("❌ Setup failed:", error.message)
    process.exit(1)
  }
}

function checkRequirements() {
  const requirements = [
    { cmd: "node --version", name: "Node.js" },
    { cmd: "python --version", name: "Python" },
    { cmd: "mysql --version", name: "MySQL" },
    { cmd: "git --version", name: "Git" },
  ]

  requirements.forEach((req) => {
    try {
      const version = execSync(req.cmd, { encoding: "utf8" }).trim()
      console.log(`✅ ${req.name}: ${version}`)
    } catch (error) {
      console.log(`❌ ${req.name}: Not installed`)
      throw new Error(`${req.name} is required but not installed`)
    }
  })
}

async function getUserConfig() {
  const questions = [
    {
      type: "input",
      name: "mysqlPassword",
      message: "Enter your MySQL root password:",
      mask: "*",
    },
    {
      type: "input",
      name: "emailAddress",
      message: "Enter your Gmail address (for notifications):",
      validate: (input) => input.includes("@gmail.com") || "Please enter a valid Gmail address",
    },
    {
      type: "input",
      name: "emailPassword",
      message: "Enter your Gmail App Password (16 characters):",
      mask: "*",
      validate: (input) => input.length === 16 || "Gmail App Password should be 16 characters",
    },
    {
      type: "input",
      name: "projectName",
      message: "Enter project name:",
      default: "expense-tracker-app",
    },
  ]

  return await inquirer.prompt(questions)
}

function createProjectStructure() {
  const dirs = ["frontend", "backend", "database", "scripts"]
  dirs.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
      console.log(`📁 Created ${dir}/`)
    }
  })
}

function setupFrontend() {
  process.chdir("frontend")

  console.log("📦 Creating Next.js application...")
  execSync('npx create-next-app@latest . --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --yes', {
    stdio: "inherit",
  })

  console.log("📦 Installing additional dependencies...")
  execSync(
    "npm install @radix-ui/react-dialog @radix-ui/react-select @radix-ui/react-tabs lucide-react chart.js react-chartjs-2 class-variance-authority clsx tailwind-merge",
    { stdio: "inherit" },
  )

  console.log("🎨 Setting up shadcn/ui...")
  execSync("npx shadcn@latest init --yes --style default --base-color slate --css-variables", { stdio: "inherit" })
  execSync("npx shadcn@latest add button card input label tabs dialog select badge toast", { stdio: "inherit" })

  process.chdir("..")
}

function setupBackend() {
  process.chdir("backend")

  console.log("🐍 Creating virtual environment...")
  execSync("python -m venv venv", { stdio: "inherit" })

  console.log("📦 Installing Python dependencies...")
  const activateCmd = process.platform === "win32" ? "venv\\Scripts\\activate" : "source venv/bin/activate"
  execSync(
    `${activateCmd} && pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-JWT-Extended Flask-Mail Flask-CORS python-dotenv PyMySQL cryptography`,
    { stdio: "inherit", shell: true },
  )

  process.chdir("..")
}

function createConfigFiles(config) {
  const envContent = `# Database Configuration
DATABASE_URL=mysql://root:${config.mysqlPassword}@localhost/expense_tracker

# JWT Configuration
SECRET_KEY=your-super-secret-key-${Date.now()}
JWT_SECRET_KEY=your-jwt-secret-key-${Date.now()}

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=${config.emailAddress}
MAIL_PASSWORD=${config.emailPassword}
MAIL_DEFAULT_SENDER=${config.emailAddress}

# Environment
FLASK_ENV=development
FLASK_DEBUG=1`

  fs.writeFileSync("backend/.env", envContent)
  console.log("✅ Created backend/.env")

  // Create database schema
  const schemaContent = `-- Create database
CREATE DATABASE IF NOT EXISTS expense_tracker;
USE expense_tracker;

-- Users table
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Expenses table
CREATE TABLE expense (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    description TEXT,
    date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

-- Income table
CREATE TABLE income (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_month_year (user_id, month, year)
);

-- Monthly limits table
CREATE TABLE monthly_limit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    limit_amount DECIMAL(10, 2) NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_limit_month_year (user_id, month, year)
);`

  fs.writeFileSync("database/schema.sql", schemaContent)
  console.log("✅ Created database/schema.sql")
}

function setupDatabase(config) {
  try {
    console.log("🗄️  Creating database...")
    execSync(`mysql -u root -p${config.mysqlPassword} < database/schema.sql`, { stdio: "inherit" })
    console.log("✅ Database created successfully")
  } catch (error) {
    console.log("⚠️  Database setup failed. You may need to run it manually:")
    console.log(`mysql -u root -p < database/schema.sql`)
  }
}

if (require.main === module) {
  main()
}
