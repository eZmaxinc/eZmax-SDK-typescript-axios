# ModuleUserApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**userCreateEzsignuserV1**](#usercreateezsignuserv1) | **POST** /1/module/user/createezsignuser | Create a new User of type Ezsignuser|

# **userCreateEzsignuserV1**
> UserCreateEzsignuserV1Response userCreateEzsignuserV1(userCreateEzsignuserV1Request)

The endpoint allows to initiate the creation or a user of type Ezsignuser.  The user will be created only once the email verification process will be completed

### Example

```typescript
import {
    ModuleUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ModuleUserApi(configuration);

let userCreateEzsignuserV1Request: Array<UserCreateEzsignuserV1Request>; //

const { status, data } = await apiInstance.userCreateEzsignuserV1(
    userCreateEzsignuserV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userCreateEzsignuserV1Request** | **Array<UserCreateEzsignuserV1Request>**|  | |


### Return type

**UserCreateEzsignuserV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

