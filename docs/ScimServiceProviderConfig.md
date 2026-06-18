# ScimServiceProviderConfig


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**authenticationSchemes** | [**Array&lt;ScimAuthenticationScheme&gt;**](ScimAuthenticationScheme.md) | A multi-valued complex type that specifies supported authentication scheme properties. | [default to undefined]
**bulk** | [**ScimServiceProviderConfigBulk**](ScimServiceProviderConfigBulk.md) |  | [default to undefined]
**changePassword** | [**ScimServiceProviderConfigChangePassword**](ScimServiceProviderConfigChangePassword.md) |  | [default to undefined]
**documentationUri** | **string** | An HTTP-addressable URL pointing to the service provider\&#39;s human-consumable help documentation | [default to undefined]
**etag** | [**ScimServiceProviderConfigChangePassword**](ScimServiceProviderConfigChangePassword.md) |  | [default to undefined]
**filter** | [**ScimServiceProviderConfigFilter**](ScimServiceProviderConfigFilter.md) |  | [default to undefined]
**patch** | [**ScimServiceProviderConfigChangePassword**](ScimServiceProviderConfigChangePassword.md) |  | [default to undefined]
**sort** | [**ScimServiceProviderConfigChangePassword**](ScimServiceProviderConfigChangePassword.md) |  | [default to undefined]

## Example

```typescript
import { ScimServiceProviderConfig } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ScimServiceProviderConfig = {
    authenticationSchemes,
    bulk,
    changePassword,
    documentationUri,
    etag,
    filter,
    patch,
    sort,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
