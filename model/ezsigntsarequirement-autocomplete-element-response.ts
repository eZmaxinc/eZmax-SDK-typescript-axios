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



/**
 * A Ezsigntsarequirement AutocompleteElement Response
 * @export
 * @interface EzsigntsarequirementAutocompleteElementResponse
 */
export interface EzsigntsarequirementAutocompleteElementResponse {
    /**
     * The description of the Ezsigntsarequirement in the language of the requester
     * @type {string}
     * @memberof EzsigntsarequirementAutocompleteElementResponse
     */
    /*'sEzsigntsarequirementDescriptionX': string;*/
    'sEzsigntsarequirementDescriptionX': string;
    /**
     * The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\'s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\'s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**|
     * @type {number}
     * @memberof EzsigntsarequirementAutocompleteElementResponse
     */
    /*'pkiEzsigntsarequirementID': number;*/
    'pkiEzsigntsarequirementID': number;
    /**
     * Whether the Ezsigntsarequirement is active or not
     * @type {boolean}
     * @memberof EzsigntsarequirementAutocompleteElementResponse
     */
    /*'bEzsigntsarequirementIsactive': boolean;*/
    'bEzsigntsarequirementIsactive': boolean;
    /**
     * Indicates if the element is disabled in the context
     * @type {boolean}
     * @memberof EzsigntsarequirementAutocompleteElementResponse
     */
    /*'bDisabled': boolean;*/
    'bDisabled': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntsarequirementAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntsarequirementAutocompleteElementResponse
 */
export class DataObjectEzsigntsarequirementAutocompleteElementResponse {
   sEzsigntsarequirementDescriptionX:string = ''
   pkiEzsigntsarequirementID:number = 0
   bEzsigntsarequirementIsactive:boolean = false
   bDisabled:boolean = false
}

/**
 * @export 
 * A EzsigntsarequirementAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzsigntsarequirementAutocompleteElementResponse
 */
export class ValidationObjectEzsigntsarequirementAutocompleteElementResponse {
   sEzsigntsarequirementDescriptionX = {
      type: 'string',
      required: true
   }
   pkiEzsigntsarequirementID = {
      type: 'integer',
      minimum: 1,
      maximum: 3,
      required: true
   }
   bEzsigntsarequirementIsactive = {
      type: 'boolean',
      required: true
   }
   bDisabled = {
      type: 'boolean',
      required: true
   }
} 


