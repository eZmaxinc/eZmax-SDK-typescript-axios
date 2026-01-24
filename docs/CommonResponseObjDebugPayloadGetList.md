# CommonResponseObjDebugPayloadGetList

This is a debug object containing debugging information on the actual function

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iVersionMin** | **number** | The minimum version of the function that can be called | [default to undefined]
**iVersionMax** | **number** | The maximum version of the function that can be called | [default to undefined]
**a_RequiredPermission** | **Array&lt;number&gt;** | An array of permissions required to access this function.  If the value \&quot;0\&quot; is present in the array, anyone can call this function.  You must have one of the permission to access the function. You don\&#39;t need to have all of them. | [default to undefined]
**bVersionDeprecated** | **boolean** | Wheter the current route is deprecated or not | [default to undefined]
**dtResponseDate** | **string** | Represent a Date Time. The timezone is the one configured in the User\&#39;s profile. | [default to undefined]
**a_Filter** | [**CommonResponseFilter**](CommonResponseFilter.md) |  | [default to undefined]
**a_OrderBy** | **{ [key: string]: string; }** | List of available values for *eOrderBy* | [default to undefined]
**iRowMax** | **number** | The maximum numbers of results to be returned.  When the content-type is **application/json** there is an implicit default of 10 000.  When it\&#39;s **application/vnd.openxmlformats-officedocument.spreadsheetml.sheet** the is no implicit default so if you do not specify iRowMax, all records will be returned. | [default to undefined]
**iRowOffset** | **number** | The starting element from where to start retrieving the results. For example if you started at iRowOffset&#x3D;0 and asked for iRowMax&#x3D;100, to get the next 100 results, you could specify iRowOffset&#x3D;100&amp;iRowMax&#x3D;100, | [default to 0]

## Example

```typescript
import { CommonResponseObjDebugPayloadGetList } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonResponseObjDebugPayloadGetList = {
    iVersionMin,
    iVersionMax,
    a_RequiredPermission,
    bVersionDeprecated,
    dtResponseDate,
    a_Filter,
    a_OrderBy,
    iRowMax,
    iRowOffset,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
