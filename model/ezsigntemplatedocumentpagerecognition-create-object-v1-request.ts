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
import type { EzsigntemplatedocumentpagerecognitionRequestCompound } from './ezsigntemplatedocumentpagerecognition-request-compound';

/**
 * Request for POST /1/object/ezsigntemplatedocumentpagerecognition
 * @export
 * @interface EzsigntemplatedocumentpagerecognitionCreateObjectV1Request
 */
export interface EzsigntemplatedocumentpagerecognitionCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatedocumentpagerecognitionRequestCompound>}
     * @memberof EzsigntemplatedocumentpagerecognitionCreateObjectV1Request
     */
    /*'a_objEzsigntemplatedocumentpagerecognition': Array<EzsigntemplatedocumentpagerecognitionRequestCompound>;*/
    'a_objEzsigntemplatedocumentpagerecognition': Array<EzsigntemplatedocumentpagerecognitionRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Request
 */
export class DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Request {
   a_objEzsigntemplatedocumentpagerecognition:Array<EzsigntemplatedocumentpagerecognitionRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Request {
   a_objEzsigntemplatedocumentpagerecognition = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


