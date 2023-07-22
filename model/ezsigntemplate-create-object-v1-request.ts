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
import { EzsigntemplateRequestCompound } from './ezsigntemplate-request-compound';

/**
 * Request for POST /1/object/ezsigntemplate
 * @export
 * @interface EzsigntemplateCreateObjectV1Request
 */
export interface EzsigntemplateCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplateRequestCompound>}
     * @memberof EzsigntemplateCreateObjectV1Request
     */
    'a_objEzsigntemplate': Array<EzsigntemplateRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateCreateObjectV1Request
 */
export class DataObjectEzsigntemplateCreateObjectV1Request {
   a_objEzsigntemplate:Array<EzsigntemplateRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplateCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplateCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplateCreateObjectV1Request {
   a_objEzsigntemplate = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


