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



/**
 * Response for PUT /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/EditEzsigntemplatedocumentpagerecognitions
 * @export
 * @interface EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload
 */
export interface EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload {
    /**
     * 
     * @type {Array<number>}
     * @memberof EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload
     */
    /*'a_pkiEzsigntemplatedocumentpagerecognitionID': Array<number>;*/
    'a_pkiEzsigntemplatedocumentpagerecognitionID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload
 */
export class DataObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload {
   a_pkiEzsigntemplatedocumentpagerecognitionID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatedocumentEditEzsigntemplatedocumentpagerecognitionsV1ResponseMPayload {
   a_pkiEzsigntemplatedocumentpagerecognitionID = {
      type: 'array',
      required: true
   }
} 


