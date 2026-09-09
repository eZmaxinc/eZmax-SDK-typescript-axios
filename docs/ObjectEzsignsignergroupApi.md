# ObjectEzsignsignergroupApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignsignergroupCreateObjectV1**](#ezsignsignergroupcreateobjectv1) | **POST** /1/object/ezsignsignergroup | Create a new Ezsignsignergroup|
|[**ezsignsignergroupDeleteObjectV1**](#ezsignsignergroupdeleteobjectv1) | **DELETE** /1/object/ezsignsignergroup/{pkiEzsignsignergroupID} | Delete an existing Ezsignsignergroup|
|[**ezsignsignergroupEditEzsignsignergroupmembershipsV1**](#ezsignsignergroupeditezsignsignergroupmembershipsv1) | **PUT** /1/object/ezsignsignergroup/{pkiEzsignsignergroupID}/editEzsignsignergroupmemberships | Edit multiple Ezsignsignergroupmemberships|
|[**ezsignsignergroupEditObjectV1**](#ezsignsignergroupeditobjectv1) | **PUT** /1/object/ezsignsignergroup/{pkiEzsignsignergroupID} | Edit an existing Ezsignsignergroup|
|[**ezsignsignergroupGetEzsignsignergroupmembershipsV1**](#ezsignsignergroupgetezsignsignergroupmembershipsv1) | **GET** /1/object/ezsignsignergroup/{pkiEzsignsignergroupID}/getEzsignsignergroupmemberships | Retrieve an existing Ezsignsignergroup\&#39;s Ezsignsignergroupmemberships|
|[**ezsignsignergroupGetObjectV2**](#ezsignsignergroupgetobjectv2) | **GET** /2/object/ezsignsignergroup/{pkiEzsignsignergroupID} | Retrieve an existing Ezsignsignergroup|

# **ezsignsignergroupCreateObjectV1**
> EzsignsignergroupCreateObjectV1Response ezsignsignergroupCreateObjectV1(ezsignsignergroupCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignsignergroupApi,
    Configuration,
    EzsignsignergroupCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupApi(configuration);

let ezsignsignergroupCreateObjectV1Request: EzsignsignergroupCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignsignergroupCreateObjectV1(
    ezsignsignergroupCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignergroupCreateObjectV1Request** | **EzsignsignergroupCreateObjectV1Request**|  | |


### Return type

**EzsignsignergroupCreateObjectV1Response**

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

# **ezsignsignergroupDeleteObjectV1**
> EzsignsignergroupDeleteObjectV1Response ezsignsignergroupDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsignsignergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupApi(configuration);

let pkiEzsignsignergroupID: number; //The unique ID of the Ezsignsignergroup (default to undefined)

const { status, data } = await apiInstance.ezsignsignergroupDeleteObjectV1(
    pkiEzsignsignergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignergroupID** | [**number**] | The unique ID of the Ezsignsignergroup | defaults to undefined|


### Return type

**EzsignsignergroupDeleteObjectV1Response**

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

# **ezsignsignergroupEditEzsignsignergroupmembershipsV1**
> EzsignsignergroupEditEzsignsignergroupmembershipsV1Response ezsignsignergroupEditEzsignsignergroupmembershipsV1(ezsignsignergroupEditEzsignsignergroupmembershipsV1Request)

Using this endpoint, you can edit multiple Ezsignsignergroupmemberships at the same time.

### Example

```typescript
import {
    ObjectEzsignsignergroupApi,
    Configuration,
    EzsignsignergroupEditEzsignsignergroupmembershipsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupApi(configuration);

let pkiEzsignsignergroupID: number; // (default to undefined)
let ezsignsignergroupEditEzsignsignergroupmembershipsV1Request: EzsignsignergroupEditEzsignsignergroupmembershipsV1Request; //

const { status, data } = await apiInstance.ezsignsignergroupEditEzsignsignergroupmembershipsV1(
    pkiEzsignsignergroupID,
    ezsignsignergroupEditEzsignsignergroupmembershipsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignergroupEditEzsignsignergroupmembershipsV1Request** | **EzsignsignergroupEditEzsignsignergroupmembershipsV1Request**|  | |
| **pkiEzsignsignergroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignergroupEditEzsignsignergroupmembershipsV1Response**

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

# **ezsignsignergroupEditObjectV1**
> EzsignsignergroupEditObjectV1Response ezsignsignergroupEditObjectV1(ezsignsignergroupEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsignsignergroupApi,
    Configuration,
    EzsignsignergroupEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupApi(configuration);

let pkiEzsignsignergroupID: number; //The unique ID of the Ezsignsignergroup (default to undefined)
let ezsignsignergroupEditObjectV1Request: EzsignsignergroupEditObjectV1Request; //

const { status, data } = await apiInstance.ezsignsignergroupEditObjectV1(
    pkiEzsignsignergroupID,
    ezsignsignergroupEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsignergroupEditObjectV1Request** | **EzsignsignergroupEditObjectV1Request**|  | |
| **pkiEzsignsignergroupID** | [**number**] | The unique ID of the Ezsignsignergroup | defaults to undefined|


### Return type

**EzsignsignergroupEditObjectV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ezsignsignergroupGetEzsignsignergroupmembershipsV1**
> EzsignsignergroupGetEzsignsignergroupmembershipsV1Response ezsignsignergroupGetEzsignsignergroupmembershipsV1()


### Example

```typescript
import {
    ObjectEzsignsignergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupApi(configuration);

let pkiEzsignsignergroupID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsignsignergroupGetEzsignsignergroupmembershipsV1(
    pkiEzsignsignergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignergroupID** | [**number**] |  | defaults to undefined|


### Return type

**EzsignsignergroupGetEzsignsignergroupmembershipsV1Response**

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

# **ezsignsignergroupGetObjectV2**
> EzsignsignergroupGetObjectV2Response ezsignsignergroupGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignsignergroupApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsignergroupApi(configuration);

let pkiEzsignsignergroupID: number; //The unique ID of the Ezsignsignergroup (default to undefined)

const { status, data } = await apiInstance.ezsignsignergroupGetObjectV2(
    pkiEzsignsignergroupID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsignergroupID** | [**number**] | The unique ID of the Ezsignsignergroup | defaults to undefined|


### Return type

**EzsignsignergroupGetObjectV2Response**

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

