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



/**
 * Payload for DELETE /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}
 * @export
 * @interface EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload
 */
export interface EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload {
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload
     */
    'bEzsigntemplatepackageNeedvalidation': boolean;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload
     */
    'bEzsignbulksendNeedvalidation': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload {
   bEzsigntemplatepackageNeedvalidation:boolean = false
   bEzsignbulksendNeedvalidation:boolean = false
}

/**
 * @export 
 * A EzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepackagesignerDeleteObjectV1ResponseMPayload {
   bEzsigntemplatepackageNeedvalidation = {
      type: 'boolean',
      required: true
   }
   bEzsignbulksendNeedvalidation = {
      type: 'boolean',
      required: true
   }
} 


