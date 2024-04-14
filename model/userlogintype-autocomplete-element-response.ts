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
 * A Userlogintype AutocompleteElement Response
 * @export
 * @interface UserlogintypeAutocompleteElementResponse
 */
export interface UserlogintypeAutocompleteElementResponse {
    /**
     * The unique ID of the Userlogintype  Valid values:  |Value|Description|Detail| |-|-|-| |1|**Email Only**|The Ezsignsigner will receive a secure link by email| |2|**Email and phone or SMS**|The Ezsignsigner will receive a secure link by email and will need to authenticate using SMS or Phone call. **Additional fee applies**| |3|**Email and secret question**|The Ezsignsigner will receive a secure link by email and will need to authenticate using a predefined question and answer| |4|**In person only**|The Ezsignsigner will only be able to sign \"In-Person\" and there won\'t be any authentication. No email will be sent for invitation to sign. Make sure you evaluate the risk of signature denial and at minimum, we recommend you use a handwritten signature type| |5|**In person with phone or SMS**|The Ezsignsigner will only be able to sign \"In-Person\" and will need to authenticate using SMS or Phone call. No email will be sent for invitation to sign. **Additional fee applies**|
     * @type {number}
     * @memberof UserlogintypeAutocompleteElementResponse
     */
    /*'pkiUserlogintypeID': number;*/
    'pkiUserlogintypeID': number;
    /**
     * The description of the Userlogintype in the language of the requester
     * @type {string}
     * @memberof UserlogintypeAutocompleteElementResponse
     */
    /*'sUserlogintypeDescriptionX': string;*/
    'sUserlogintypeDescriptionX': string;
    /**
     * Whether the Userlogintype is active or not
     * @type {boolean}
     * @memberof UserlogintypeAutocompleteElementResponse
     */
    /*'bUserlogintypeIsactive': boolean;*/
    'bUserlogintypeIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserlogintypeAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserlogintypeAutocompleteElementResponse
 */
export class DataObjectUserlogintypeAutocompleteElementResponse {
   pkiUserlogintypeID:number = 0
   sUserlogintypeDescriptionX:string = ''
   bUserlogintypeIsactive:boolean = false
}

/**
 * @export 
 * A UserlogintypeAutocompleteElementResponse Validation Object
 * @class ValidationObjectUserlogintypeAutocompleteElementResponse
 */
export class ValidationObjectUserlogintypeAutocompleteElementResponse {
   pkiUserlogintypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sUserlogintypeDescriptionX = {
      type: 'string',
      required: true
   }
   bUserlogintypeIsactive = {
      type: 'boolean',
      required: true
   }
} 


