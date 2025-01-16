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
import type { CustomBrandingResponse } from './custom-branding-response';

/**
 * Payload for POST /1/object/ezsigntemplatepublic/getEzsigntemplatepublicDetails
 * @export
 * @interface EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload
 */
export interface EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload {
    /**
     * 
     * @type {CustomBrandingResponse}
     * @memberof EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload
     */
    /*'objBranding'?: CustomBrandingResponse;*/
    'objBranding'?: CustomBrandingResponse;
    /**
     * The unique ID of the Userlogintype  Valid values:  |Value|Description|Detail| |-|-|-| |1|**Email Only**|The Ezsignsigner will receive a secure link by email| |2|**Email and phone or SMS**|The Ezsignsigner will receive a secure link by email and will need to authenticate using SMS or Phone call. **Additional fee applies**| |3|**Email and secret question**|The Ezsignsigner will receive a secure link by email and will need to authenticate using a predefined question and answer| |4|**In person only**|The Ezsignsigner will only be able to sign \"In-Person\" and there won\'t be any authentication. No email will be sent for invitation to sign. Make sure you evaluate the risk of signature denial and at minimum, we recommend you use a handwritten signature type| |5|**In person with phone or SMS**|The Ezsignsigner will only be able to sign \"In-Person\" and will need to authenticate using SMS or Phone call. No email will be sent for invitation to sign. **Additional fee applies**| |6|**Embedded**|The Ezsignsigner will only be able to sign in the embedded solution. No email will be sent for invitation to sign. **Additional fee applies**|   |7|**Embedded with phone or SMS**|The Ezsignsigner will only be able to sign in the embedded solution and will need to authenticate using SMS or Phone call. No email will be sent for invitation to sign. **Additional fee applies**|   |8|**No validation**|The Ezsignsigner will not receive an email and won\'t have to validate his connection using 2 factor. **Additional fee applies**|      |9|**Sms only**|The Ezsignsigner will not receive an email but will will need to authenticate using SMS. **Additional fee applies**|     
     * @type {number}
     * @memberof EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload
     */
    /*'fkiUserlogintypeID': number;*/
    'fkiUserlogintypeID': number;
    /**
     * 
     * @type {Array<string>}
     * @memberof EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload
     */
    /*'a_sEzsigntemplatesignerDescription': Array<string>;*/
    'a_sEzsigntemplatesignerDescription': Array<string>;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomBrandingResponse } from './'
// @ts-ignore
import { ValidationObjectCustomBrandingResponse } from './'

/**
 * @export 
 * A EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload {
   objBranding?:CustomBrandingResponse = undefined
   fkiUserlogintypeID:number = 0
   a_sEzsigntemplatesignerDescription:Array<string> = []
}

/**
 * @export 
 * A EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload {
   objBranding = new ValidationObjectCustomBrandingResponse()
   fkiUserlogintypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   a_sEzsigntemplatesignerDescription = {
      type: 'array',
      required: true
   }
} 


