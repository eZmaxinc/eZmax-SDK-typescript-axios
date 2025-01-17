/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignsignergroupCreateObjectV1ResponseMPayload } from './ezsignsignergroup-create-object-v1-response-mpayload';

/**
 * @type EzsignsignergroupCreateObjectV1Response
 * Response for POST /1/object/ezsignsignergroup
 * @export
 */
/*export type EzsignsignergroupCreateObjectV1Response = CommonResponse;*/
export interface EzsignsignergroupCreateObjectV1Response {
    /**
     * 
     * @type {EzsignsignergroupCreateObjectV1ResponseMPayload}
     * @memberof EzsignsignergroupCreateObjectV1Response
     */
    mPayload:EzsignsignergroupCreateObjectV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignergroupCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignsignergroupCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignergroupCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupCreateObjectV1Response
 */
export class DataObjectEzsignsignergroupCreateObjectV1Response {
    mPayload:EzsignsignergroupCreateObjectV1ResponseMPayload = new DataObjectEzsignsignergroupCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignergroupCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignsignergroupCreateObjectV1Response
 */
export class ValidationObjectEzsignsignergroupCreateObjectV1Response {
   mPayload = new ValidationObjectEzsignsignergroupCreateObjectV1ResponseMPayload()
} 


