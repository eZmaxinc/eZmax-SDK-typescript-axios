/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './ezsignbulksendsignermapping-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignbulksendsignermappingCreateObjectV1ResponseAllOf
 */
export interface EzsignbulksendsignermappingCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendsignermappingCreateObjectV1ResponseMPayload}
     * @memberof EzsignbulksendsignermappingCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsignbulksendsignermappingCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseAllOf
 */
export class DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseAllOf {
   mPayload:EzsignbulksendsignermappingCreateObjectV1ResponseMPayload = new DataObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendsignermappingCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseAllOf
 */
export class ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignbulksendsignermappingCreateObjectV1ResponseMPayload()
} 


