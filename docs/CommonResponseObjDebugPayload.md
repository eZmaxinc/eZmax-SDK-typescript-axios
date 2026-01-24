# CommonResponseObjDebugPayload

This is a debug object containing debugging information on the actual function

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iVersionMin** | **number** | The minimum version of the function that can be called | [default to undefined]
**iVersionMax** | **number** | The maximum version of the function that can be called | [default to undefined]
**a_RequiredPermission** | **Array&lt;number&gt;** | An array of permissions required to access this function.  If the value \&quot;0\&quot; is present in the array, anyone can call this function.  You must have one of the permission to access the function. You don\&#39;t need to have all of them. | [default to undefined]
**bVersionDeprecated** | **boolean** | Wheter the current route is deprecated or not | [default to undefined]
**dtResponseDate** | **string** | Represent a Date Time. The timezone is the one configured in the User\&#39;s profile. | [default to undefined]

## Example

```typescript
import { CommonResponseObjDebugPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonResponseObjDebugPayload = {
    iVersionMin,
    iVersionMax,
    a_RequiredPermission,
    bVersionDeprecated,
    dtResponseDate,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
