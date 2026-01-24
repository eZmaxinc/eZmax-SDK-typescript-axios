# ScimUser


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **string** |  | [optional] [default to undefined]
**userName** | **string** | A service provider\&#39;s unique identifier for the user, typically used by the user to directly authenticate to the service provider.  Often displayed to the user as their unique identifier within the system (as opposed to \&quot;id\&quot; or \&quot;externalId\&quot;, which are generally opaque and not user-friendly identifiers).  Each User MUST include a non-empty userName value.  This identifier MUST be unique across the service provider\&#39;s entire set of Users.  This attribute is REQUIRED and is case insensitive. | [default to undefined]
**displayName** | **string** |  | [optional] [default to undefined]
**emails** | [**Array&lt;ScimEmail&gt;**](ScimEmail.md) |  | [optional] [default to undefined]

## Example

```typescript
import { ScimUser } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ScimUser = {
    id,
    userName,
    displayName,
    emails,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
