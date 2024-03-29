/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './ezsignbulksenddocumentmapping-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
 */
export interface EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload}
     * @memberof EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
     */
    'mPayload': EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
 */
export class DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseAllOf {
   mPayload:EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload = new DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
 */
export class ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload()
} 


