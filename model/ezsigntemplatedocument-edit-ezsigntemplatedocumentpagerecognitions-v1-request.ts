/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
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
 * Request for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/editEzsigntemplatedocumentpagerecognitions
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request
 */
export interface EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatedocumentpagerecognitionRequestCompound>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request
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
 * A EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request {
   a_objEzsigntemplatedocumentpagerecognition:Array<EzsigntemplatedocumentpagerecognitionRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1Request {
   a_objEzsigntemplatedocumentpagerecognition = {
      type: 'array',
      required: true
   }
} 


