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
import { EzsigntemplateRequestCompoundV2 } from './ezsigntemplate-request-compound-v2';

/**
 * Request for POST /2/object/ezsigntemplate
 * @export
 * @interface EzsigntemplateCreateObjectV2Request
 */
export interface EzsigntemplateCreateObjectV2Request {
    /**
     * 
     * @type {Array<EzsigntemplateRequestCompoundV2>}
     * @memberof EzsigntemplateCreateObjectV2Request
     */
    /*'a_objEzsigntemplate': Array<EzsigntemplateRequestCompoundV2>;*/
    'a_objEzsigntemplate': Array<EzsigntemplateRequestCompoundV2>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateCreateObjectV2Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateCreateObjectV2Request
 */
export class DataObjectEzsigntemplateCreateObjectV2Request {
   a_objEzsigntemplate:Array<EzsigntemplateRequestCompoundV2> = []
}

/**
 * @export 
 * A EzsigntemplateCreateObjectV2Request Validation Object
 * @class ValidationObjectEzsigntemplateCreateObjectV2Request
 */
export class ValidationObjectEzsigntemplateCreateObjectV2Request {
   a_objEzsigntemplate = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


