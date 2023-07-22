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
import { EzsignbulksendRequestCompound } from './ezsignbulksend-request-compound';

/**
 * Request for POST /1/object/ezsignbulksend
 * @export
 * @interface EzsignbulksendCreateObjectV1Request
 */
export interface EzsignbulksendCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignbulksendRequestCompound>}
     * @memberof EzsignbulksendCreateObjectV1Request
     */
    'a_objEzsignbulksend': Array<EzsignbulksendRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendCreateObjectV1Request
 */
export class DataObjectEzsignbulksendCreateObjectV1Request {
   a_objEzsignbulksend:Array<EzsignbulksendRequestCompound> = []
}

/**
 * @export 
 * A EzsignbulksendCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsignbulksendCreateObjectV1Request
 */
export class ValidationObjectEzsignbulksendCreateObjectV1Request {
   a_objEzsignbulksend = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


