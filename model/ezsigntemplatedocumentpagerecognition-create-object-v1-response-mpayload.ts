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
 * Payload for POST /1/object/ezsigntemplatedocumentpagerecognition
 * @export
 * @interface EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload
 */
export interface EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload
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
 * A EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload
 */
export class DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload {
   a_pkiEzsigntemplatedocumentpagerecognitionID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload {
   a_pkiEzsigntemplatedocumentpagerecognitionID = {
      type: 'array',
      required: true
   }
} 


