# ObjectEzsignsignergroupmembershipApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignsignergroupmembershipCreateObjectV1**](#ezsignsignergroupmembershipcreateobjectv1) | **POST** /1/object/ezsignsignergroupmembership | Create a new Ezsignsignergroupmembership|
|[**ezsignsignergroupmembershipDeleteObjectV1**](#ezsignsignergroupmembershipdeleteobjectv1) | **DELETE** /1/object/ezsignsignergroupmembership/{pkiEzsignsignergroupmembershipID} | Delete an existing Ezsignsignergroupmembership|
|[**ezsignsignergroupmembershipGetObjectV2**](#ezsignsignergroupmembershipgetobjectv2) | **GET** /2/object/ezsignsignergroupmembership/{pkiEzsignsignergroupmembershipID} | Retrieve an existing Ezsignsignergroupmembership|

# **ezsignsignergroupmembershipCreateObjectV1**
> EzsignsignergroupmembershipCreateObjectV1Response ezsignsignergroupmembershipCreateObjectV1(ezsignsignergroupmembershipCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignsignergroupmembershipApi,
    Configuration,
    EzsignsignergroupmembershipCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupmembershipApi(configuration);

let ezsignsignergroupmembershipCreateObjectV1Request: EzsignsignergroupmembershipCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignsignergroupmembershipCreateObjectV1(
    ezsignsignergroupmembershipCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignergroupmembershipCreateObjectV1Request** | **EzsignsignergroupmembershipCreateObjectV1Request**|  | |


### Return type

**EzsignsignergroupmembershipCreateObjectV1Response**

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

# **ezsignsignergroupmembershipDeleteObjectV1**
> EzsignsignergroupmembershipDeleteObjectV1Response ezsignsignergroupmembershipDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignsignergroupmembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupmembershipApi(configuration);

let pkiEzsignsignergroupmembershipID: number; //The unique ID of the Ezsignsignergroupmembership (default to undefined)

const { status, data } = await apiInstance.ezsignsignergroupmembershipDeleteObjectV1(
    pkiEzsignsignergroupmembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignergroupmembershipID** | [**number**] | The unique ID of the Ezsignsignergroupmembership | defaults to undefined|


### Return type

**EzsignsignergroupmembershipDeleteObjectV1Response**

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

# **ezsignsignergroupmembershipGetObjectV2**
> EzsignsignergroupmembershipGetObjectV2Response ezsignsignergroupmembershipGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignsignergroupmembershipApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupmembershipApi(configuration);

let pkiEzsignsignergroupmembershipID: number; //The unique ID of the Ezsignsignergroupmembership (default to undefined)

const { status, data } = await apiInstance.ezsignsignergroupmembershipGetObjectV2(
    pkiEzsignsignergroupmembershipID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignergroupmembershipID** | [**number**] | The unique ID of the Ezsignsignergroupmembership | defaults to undefined|


### Return type

**EzsignsignergroupmembershipGetObjectV2Response**

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

