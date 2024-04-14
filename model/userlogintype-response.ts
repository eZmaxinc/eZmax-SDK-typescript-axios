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
import { MultilingualUserlogintypeDescription } from './multilingual-userlogintype-description';

/**
 * An Userlogintype Object
 * @export
 * @interface UserlogintypeResponse
 */
export interface UserlogintypeResponse {
    /**
     * The unique ID of the Userlogintype  Valid values:  |Value|Description|Detail| |-|-|-| |1|**Email Only**|The Ezsignsigner will receive a secure link by email| |2|**Email and phone or SMS**|The Ezsignsigner will receive a secure link by email and will need to authenticate using SMS or Phone call. **Additional fee applies**| |3|**Email and secret question**|The Ezsignsigner will receive a secure link by email and will need to authenticate using a predefined question and answer| |4|**In person only**|The Ezsignsigner will only be able to sign \"In-Person\" and there won\'t be any authentication. No email will be sent for invitation to sign. Make sure you evaluate the risk of signature denial and at minimum, we recommend you use a handwritten signature type| |5|**In person with phone or SMS**|The Ezsignsigner will only be able to sign \"In-Person\" and will need to authenticate using SMS or Phone call. No email will be sent for invitation to sign. **Additional fee applies**|
     * @type {number}
     * @memberof UserlogintypeResponse
     */
    /*'pkiUserlogintypeID': number;*/
    'pkiUserlogintypeID': number;
    /**
     * 
     * @type {MultilingualUserlogintypeDescription}
     * @memberof UserlogintypeResponse
     */
    /*'objUserlogintypeDescription': MultilingualUserlogintypeDescription;*/
    'objUserlogintypeDescription': MultilingualUserlogintypeDescription;
    /**
     * The description of the Userlogintype in the language of the requester
     * @type {string}
     * @memberof UserlogintypeResponse
     */
    /*'sUserlogintypeDescriptionX': string;*/
    'sUserlogintypeDescriptionX': string;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualUserlogintypeDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualUserlogintypeDescription } from './'

/**
 * @export 
 * A UserlogintypeResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserlogintypeResponse
 */
export class DataObjectUserlogintypeResponse {
   pkiUserlogintypeID:number = 0
   objUserlogintypeDescription:MultilingualUserlogintypeDescription = new DataObjectMultilingualUserlogintypeDescription()
   sUserlogintypeDescriptionX:string = ''
}

/**
 * @export 
 * A UserlogintypeResponse Validation Object
 * @class ValidationObjectUserlogintypeResponse
 */
export class ValidationObjectUserlogintypeResponse {
   pkiUserlogintypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objUserlogintypeDescription = new ValidationObjectMultilingualUserlogintypeDescription()
   sUserlogintypeDescriptionX = {
      type: 'string',
      required: true
   }
} 

