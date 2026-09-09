# ObjectUsergroupmembershipApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**usergroupmembershipCreateObjectV1**](#usergroupmembershipcreateobjectv1) | **POST** /1/object/usergroupmembership | Create a new Usergroupmembership|
|[**usergroupmembershipDeleteObjectV1**](#usergroupmembershipdeleteobjectv1) | **DELETE** /1/object/usergroupmembership/{pkiUsergroupmembershipID} | Delete an existing Usergroupmembership|
|[**usergroupmembershipEditObjectV1**](#usergroupmembershipeditobjectv1) | **PUT** /1/object/usergroupmembership/{pkiUsergroupmembershipID} | Edit an existing Usergroupmembership|
|[**usergroupmembershipGetObjectV2**](#usergroupmembershipgetobjectv2) | **GET** /2/object/usergroupmembership/{pkiUsergroupmembershipID} | Retrieve an existing Usergroupmembership|

# **usergroupmembershipCreateObjectV1**
> UsergroupmembershipCreateObjectV1Response usergroupmembershipCreateObjectV1(usergroupmembershipCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectUsergroupmembershipApi,
    Configuration,
    UsergroupmembershipCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupmembershipApi(configuration);

let usergroupmembershipCreateObjectV1Request: UsergroupmembershipCreateObjectV1Request; //

const { status, data } = await apiInstance.usergroupmembershipCreateObjectV1(
    usergroupmembershipCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupmembershipCreateObjectV1Request** | **UsergroupmembershipCreateObjectV1Request**|  | |


### Return type

**UsergroupmembershipCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupmembershipDeleteObjectV1**
> UsergroupmembershipDeleteObjectV1Response usergroupmembershipDeleteObjectV1()



### Example

```typescript
import {
    ObjectUsergroupmembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupmembershipApi(configuration);

let pkiUsergroupmembershipID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupmembershipDeleteObjectV1(
    pkiUsergroupmembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupmembershipID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupmembershipDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupmembershipEditObjectV1**
> UsergroupmembershipEditObjectV1Response usergroupmembershipEditObjectV1(usergroupmembershipEditObjectV1Request)



### Example

```typescript
import {
    ObjectUsergroupmembershipApi,
    Configuration,
    UsergroupmembershipEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupmembershipApi(configuration);

let pkiUsergroupmembershipID: number; // (default to undefined)
let usergroupmembershipEditObjectV1Request: UsergroupmembershipEditObjectV1Request; //

const { status, data } = await apiInstance.usergroupmembershipEditObjectV1(
    pkiUsergroupmembershipID,
    usergroupmembershipEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **usergroupmembershipEditObjectV1Request** | **UsergroupmembershipEditObjectV1Request**|  | |
| **pkiUsergroupmembershipID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupmembershipEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **usergroupmembershipGetObjectV2**
> UsergroupmembershipGetObjectV2Response usergroupmembershipGetObjectV2()



### Example

```typescript
import {
    ObjectUsergroupmembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUsergroupmembershipApi(configuration);

let pkiUsergroupmembershipID: number; // (default to undefined)

const { status, data } = await apiInstance.usergroupmembershipGetObjectV2(
    pkiUsergroupmembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUsergroupmembershipID** | [**number**] |  | defaults to undefined|


### Return type

**UsergroupmembershipGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

