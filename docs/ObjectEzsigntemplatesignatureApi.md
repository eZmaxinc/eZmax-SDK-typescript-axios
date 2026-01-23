# ObjectEzsigntemplatesignatureApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsigntemplatesignatureCreateObjectV2**](#ezsigntemplatesignaturecreateobjectv2) | **POST** /2/object/ezsigntemplatesignature | Create a new Ezsigntemplatesignature|
|[**ezsigntemplatesignatureCreateObjectV3**](#ezsigntemplatesignaturecreateobjectv3) | **POST** /3/object/ezsigntemplatesignature | Create a new Ezsigntemplatesignature|
|[**ezsigntemplatesignatureDeleteObjectV1**](#ezsigntemplatesignaturedeleteobjectv1) | **DELETE** /1/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID} | Delete an existing Ezsigntemplatesignature|
|[**ezsigntemplatesignatureEditObjectV3**](#ezsigntemplatesignatureeditobjectv3) | **PUT** /3/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID} | Edit an existing Ezsigntemplatesignature|
|[**ezsigntemplatesignatureGetObjectV4**](#ezsigntemplatesignaturegetobjectv4) | **GET** /4/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID} | Retrieve an existing Ezsigntemplatesignature|

# **ezsigntemplatesignatureCreateObjectV2**
> EzsigntemplatesignatureCreateObjectV2Response ezsigntemplatesignatureCreateObjectV2(ezsigntemplatesignatureCreateObjectV2Request)

The endpoint allows to create one or many elements at once.  Major step overhaul.  Endpoints that existed before version 1.3 do not allow you to combine forms and signatures in the same step. The step numbers are different from those indicated by endpoints added since version 1.3. This endpoint is compatible with endpoints that existed before 1.3 but are not compatible with those added since 1.3.

### Example

```typescript
import {
    ObjectEzsigntemplatesignatureApi,
    Configuration,
    EzsigntemplatesignatureCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignatureApi(configuration);

let ezsigntemplatesignatureCreateObjectV2Request: EzsigntemplatesignatureCreateObjectV2Request; //

const { status, data } = await apiInstance.ezsigntemplatesignatureCreateObjectV2(
    ezsigntemplatesignatureCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignatureCreateObjectV2Request** | **EzsigntemplatesignatureCreateObjectV2Request**|  | |


### Return type

**EzsigntemplatesignatureCreateObjectV2Response**

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

# **ezsigntemplatesignatureCreateObjectV3**
> EzsigntemplatesignatureCreateObjectV3Response ezsigntemplatesignatureCreateObjectV3(ezsigntemplatesignatureCreateObjectV3Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsigntemplatesignatureApi,
    Configuration,
    EzsigntemplatesignatureCreateObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignatureApi(configuration);

let ezsigntemplatesignatureCreateObjectV3Request: EzsigntemplatesignatureCreateObjectV3Request; //

const { status, data } = await apiInstance.ezsigntemplatesignatureCreateObjectV3(
    ezsigntemplatesignatureCreateObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignatureCreateObjectV3Request** | **EzsigntemplatesignatureCreateObjectV3Request**|  | |


### Return type

**EzsigntemplatesignatureCreateObjectV3Response**

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

# **ezsigntemplatesignatureDeleteObjectV1**
> EzsigntemplatesignatureDeleteObjectV1Response ezsigntemplatesignatureDeleteObjectV1()



### Example

```typescript
import {
    ObjectEzsigntemplatesignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignatureApi(configuration);

let pkiEzsigntemplatesignatureID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatesignatureDeleteObjectV1(
    pkiEzsigntemplatesignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatesignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignatureDeleteObjectV1Response**

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

# **ezsigntemplatesignatureEditObjectV3**
> EzsigntemplatesignatureEditObjectV3Response ezsigntemplatesignatureEditObjectV3(ezsigntemplatesignatureEditObjectV3Request)



### Example

```typescript
import {
    ObjectEzsigntemplatesignatureApi,
    Configuration,
    EzsigntemplatesignatureEditObjectV3Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignatureApi(configuration);

let pkiEzsigntemplatesignatureID: number; // (default to undefined)
let ezsigntemplatesignatureEditObjectV3Request: EzsigntemplatesignatureEditObjectV3Request; //

const { status, data } = await apiInstance.ezsigntemplatesignatureEditObjectV3(
    pkiEzsigntemplatesignatureID,
    ezsigntemplatesignatureEditObjectV3Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsigntemplatesignatureEditObjectV3Request** | **EzsigntemplatesignatureEditObjectV3Request**|  | |
| **pkiEzsigntemplatesignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignatureEditObjectV3Response**

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

# **ezsigntemplatesignatureGetObjectV4**
> EzsigntemplatesignatureGetObjectV4Response ezsigntemplatesignatureGetObjectV4()



### Example

```typescript
import {
    ObjectEzsigntemplatesignatureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsigntemplatesignatureApi(configuration);

let pkiEzsigntemplatesignatureID: number; // (default to undefined)

const { status, data } = await apiInstance.ezsigntemplatesignatureGetObjectV4(
    pkiEzsigntemplatesignatureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsigntemplatesignatureID** | [**number**] |  | defaults to undefined|


### Return type

**EzsigntemplatesignatureGetObjectV4Response**

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

