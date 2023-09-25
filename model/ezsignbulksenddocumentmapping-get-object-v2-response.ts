/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './ezsignbulksenddocumentmapping-get-object-v2-response-mpayload';

/**
 * @type EzsignbulksenddocumentmappingGetObjectV2Response
 * Response for GET /2/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID}
 * @export
 */
/** export type EzsignbulksenddocumentmappingGetObjectV2Response = CommonResponse; */
export interface EzsignbulksenddocumentmappingGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksenddocumentmappingGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksenddocumentmappingGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload}
     * @memberof EzsignbulksenddocumentmappingGetObjectV2Response
     */
    mPayload:EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksenddocumentmappingGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingGetObjectV2Response
 */
export class DataObjectEzsignbulksenddocumentmappingGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload = new DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingGetObjectV2Response
 */
export class ValidationObjectEzsignbulksenddocumentmappingGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload()
} 


