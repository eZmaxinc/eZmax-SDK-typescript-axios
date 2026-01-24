# ScimGroup


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **string** |  | [optional] [default to undefined]
**displayName** | **string** | The Name of the Usergroup in the language of the requester | [default to undefined]
**members** | [**Array&lt;ScimGroupMember&gt;**](ScimGroupMember.md) |  | [optional] [default to undefined]

## Example

```typescript
import { ScimGroup } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ScimGroup = {
    id,
    displayName,
    members,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
