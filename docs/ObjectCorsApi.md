# ObjectCorsApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**corsCreateObjectV1**](#corscreateobjectv1) | **POST** /1/object/cors | Create a new Cors|
|[**corsDeleteObjectV1**](#corsdeleteobjectv1) | **DELETE** /1/object/cors/{pkiCorsID} | Delete an existing Cors|
|[**corsEditObjectV1**](#corseditobjectv1) | **PUT** /1/object/cors/{pkiCorsID} | Edit an existing Cors|
|[**corsGetObjectV2**](#corsgetobjectv2) | **GET** /2/object/cors/{pkiCorsID} | Retrieve an existing Cors|

# **corsCreateObjectV1**
> CorsCreateObjectV1Response corsCreateObjectV1(corsCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectCorsApi,
    Configuration,
    CorsCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCorsApi(configuration);

let corsCreateObjectV1Request: CorsCreateObjectV1Request; //

const { status, data } = await apiInstance.corsCreateObjectV1(
    corsCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **corsCreateObjectV1Request** | **CorsCreateObjectV1Request**|  | |


### Return type

**CorsCreateObjectV1Response**

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

# **corsDeleteObjectV1**
> CorsDeleteObjectV1Response corsDeleteObjectV1()



### Example

```typescript
import {
    ObjectCorsApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCorsApi(configuration);

let pkiCorsID: number; //The unique ID of the Cors (default to undefined)

const { status, data } = await apiInstance.corsDeleteObjectV1(
    pkiCorsID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCorsID** | [**number**] | The unique ID of the Cors | defaults to undefined|


### Return type

**CorsDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **corsEditObjectV1**
> CorsEditObjectV1Response corsEditObjectV1(corsEditObjectV1Request)



### Example

```typescript
import {
    ObjectCorsApi,
    Configuration,
    CorsEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCorsApi(configuration);

let pkiCorsID: number; //The unique ID of the Cors (default to undefined)
let corsEditObjectV1Request: CorsEditObjectV1Request; //

const { status, data } = await apiInstance.corsEditObjectV1(
    pkiCorsID,
    corsEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **corsEditObjectV1Request** | **CorsEditObjectV1Request**|  | |
| **pkiCorsID** | [**number**] | The unique ID of the Cors | defaults to undefined|


### Return type

**CorsEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **corsGetObjectV2**
> CorsGetObjectV2Response corsGetObjectV2()



### Example

```typescript
import {
    ObjectCorsApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCorsApi(configuration);

let pkiCorsID: number; //The unique ID of the Cors (default to undefined)

const { status, data } = await apiInstance.corsGetObjectV2(
    pkiCorsID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCorsID** | [**number**] | The unique ID of the Cors | defaults to undefined|


### Return type

**CorsGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

