using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using Nethereum.UI;
using System.Security.Claims;
using System.Linq;

namespace Nethereum.Blazor
{
    public class EthAddresses
    {
        public sealed class Admin
        {
            public static string Owner => "0x2Df04451f8Dc049D23B7901a79a9f65856C5956D".ToLower();

            public static string[] Admins => new[] { "0x44E768c7e21bA56C12B5c83f1868638fd55637D0".ToLower(), "0xE77F20946533C2C9C036644025b74F9B187112D4".ToLower(), "0x2Df04451f8Dc049D23B7901a79a9f65856C5956D".ToLower(), "0x5b81bC64A8b6e62c61bB8241B20848a4b43F79C0".ToLower(), "0xd4988eFC1673fA43fFccC01E60e5c82CdD8A7F36".ToLower() };
        }
    }

    public class EthereumAuthenticationStateProvider : AuthenticationStateProvider, IDisposable
    {
        protected IEthereumHostProvider EthereumHostProvider { get; set; }
        protected SelectedEthereumHostProviderService SelectedHostProviderService { get; }

        public EthereumAuthenticationStateProvider(SelectedEthereumHostProviderService selectedHostProviderService)
        {
            SelectedHostProviderService = selectedHostProviderService;
            SelectedHostProviderService.SelectedHostProviderChanged += SelectedHostProviderChanged;
            InitSelectedHostProvider();
        }

        public void NotifyStateHasChanged()
        {
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        private Task SelectedHostProviderChanged(IEthereumHostProvider newEthereumHostProvider)
        {
            if(EthereumHostProvider != newEthereumHostProvider)
            {
                if(EthereumHostProvider != null)
                {
                    EthereumHostProvider.SelectedAccountChanged -= SelectedAccountChanged;
                }
                InitSelectedHostProvider();
            }

            return Task.CompletedTask;
           
        }

        public void InitSelectedHostProvider()
        {
            EthereumHostProvider = SelectedHostProviderService.SelectedHost;
            if (SelectedHostProviderService.SelectedHost != null)
            {
                EthereumHostProvider.SelectedAccountChanged += SelectedAccountChanged;
            }
        }

        private async Task SelectedAccountChanged(string ethereumAddress)
        {
            if(string.IsNullOrEmpty(ethereumAddress))
            {
                await NotifyAuthenticationStateAsEthereumDisconnected();
            }
            else
            {
                await NotifyAuthenticationStateAsEthereumConnected(ethereumAddress);
            }
        }

        public async override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (EthereumHostProvider != null && EthereumHostProvider.Available)
            {
                var currentAddress = await EthereumHostProvider.GetProviderSelectedAccountAsync();
                if (currentAddress != null)
                {
                    var claimsPrincipal = GetClaimsPrincipal(currentAddress);
                    return new AuthenticationState(claimsPrincipal);
                }
            }
           
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        public async Task NotifyAuthenticationStateAsEthereumConnected()
        {
            var currentAddress = await EthereumHostProvider.GetProviderSelectedAccountAsync();
            await NotifyAuthenticationStateAsEthereumConnected(currentAddress);
        }

        public async Task NotifyAuthenticationStateAsEthereumConnected(string currentAddress)
        {
            var claimsPrincipal = GetClaimsPrincipal(currentAddress);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        public async Task NotifyAuthenticationStateAsEthereumDisconnected()
        {
            var identity = new ClaimsIdentity();
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }

        private ClaimsPrincipal GetClaimsPrincipal(string ethereumAddress)
        {
            Claim claimEthereumAddress;
            Claim claimEthereumConnectedRole;
            ClaimsIdentity claimsIdentity;
            ClaimsPrincipal claimsPrincipal;

            if (ethereumAddress.ToLower() == EthAddresses.Admin.Owner)
            {
                claimEthereumAddress = new Claim(ClaimTypes.NameIdentifier, ethereumAddress);
                claimEthereumConnectedRole = new Claim(ClaimTypes.Role, "OwnerConnected");

                claimsIdentity = new ClaimsIdentity(new[] { claimEthereumAddress, claimEthereumConnectedRole }, "ownerConnected");
                claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            }
            else if(EthAddresses.Admin.Admins.Contains(ethereumAddress.ToLower()))
            {
                claimEthereumAddress = new Claim(ClaimTypes.NameIdentifier, ethereumAddress);
                claimEthereumConnectedRole = new Claim(ClaimTypes.Role, "AdminConnected");

                claimsIdentity = new ClaimsIdentity(new[] { claimEthereumAddress, claimEthereumConnectedRole }, "adminConnected");
                claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            }
            else
            {
                claimEthereumAddress = new Claim(ClaimTypes.NameIdentifier, ethereumAddress);
                claimEthereumConnectedRole = new Claim(ClaimTypes.Role, "EthereumConnected");

                claimsIdentity = new ClaimsIdentity(new[] { claimEthereumAddress, claimEthereumConnectedRole }, "ethereumConnection");
                claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            }

            Console.WriteLine(claimEthereumConnectedRole.Value);
            Console.WriteLine(ethereumAddress);

            return claimsPrincipal;
        }

        public void Dispose()
        {
            if (EthereumHostProvider != null)
            {
                EthereumHostProvider.SelectedAccountChanged -= SelectedAccountChanged;
            }

            if (SelectedHostProviderService != null)
            {
                SelectedHostProviderService.SelectedHostProviderChanged -= SelectedHostProviderChanged;
            }
        }
    }
}