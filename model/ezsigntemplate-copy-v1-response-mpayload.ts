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
 * Payload for POST /1/object/ezsigntemplate/{pkiEzsigntemplateID}/copy
 * @export
 * @interface EzsigntemplateCopyV1ResponseMPayload
 */
export interface EzsigntemplateCopyV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be copied.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof EzsigntemplateCopyV1ResponseMPayload
     */
    /*'a_pkiEzsigntemplateID': Array<number>;*/
    'a_pkiEzsigntemplateID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateCopyV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateCopyV1ResponseMPayload
 */
export class DataObjectEzsigntemplateCopyV1ResponseMPayload {
   a_pkiEzsigntemplateID:Array<number> = []
}

/**
 * @export 
 * A EzsigntemplateCopyV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplateCopyV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplateCopyV1ResponseMPayload {
   a_pkiEzsigntemplateID = {
      type: 'array',
      required: true
   }
} 


