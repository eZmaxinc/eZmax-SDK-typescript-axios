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
 * Response for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/ExtractText
 * @export
 * @interface EzsigndocumentExtractTextV1ResponseMPayload
 */
export interface EzsigndocumentExtractTextV1ResponseMPayload {
    /**
     * The text extract from document
     * @type {string}
     * @memberof EzsigndocumentExtractTextV1ResponseMPayload
     */
    /*'sText': string;*/
    'sText': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigndocumentExtractTextV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentExtractTextV1ResponseMPayload
 */
export class DataObjectEzsigndocumentExtractTextV1ResponseMPayload {
   sText:string = ''
}

/**
 * @export 
 * A EzsigndocumentExtractTextV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentExtractTextV1ResponseMPayload
 */
export class ValidationObjectEzsigndocumentExtractTextV1ResponseMPayload {
   sText = {
      type: 'string',
      required: true
   }
} 


