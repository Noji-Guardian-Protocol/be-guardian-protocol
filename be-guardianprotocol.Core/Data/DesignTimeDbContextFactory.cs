using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace be_guardianprotocol.Core.Data
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<GuardianProtocolDbContext>
    {
        public GuardianProtocolDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<GuardianProtocolDbContext>();
            optionsBuilder.UseSqlServer("");

            return new GuardianProtocolDbContext(optionsBuilder.Options);
        }
    }
}