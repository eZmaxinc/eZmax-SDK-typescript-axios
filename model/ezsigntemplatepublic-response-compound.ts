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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomEzsignfolderezsigntemplatepublicResponse } from './custom-ezsignfolderezsigntemplatepublic-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepublicResponse } from './ezsigntemplatepublic-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatepublicLimittype } from './field-eezsigntemplatepublic-limittype';

/**
 * @type EzsigntemplatepublicResponseCompound
 * A Ezsigntemplatepublic Object
 * @export
 */
/*export type EzsigntemplatepublicResponseCompound = EzsigntemplatepublicResponse;*/
export interface EzsigntemplatepublicResponseCompound {
    /**
     * The unique ID of the Ezsigntemplatepublic
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    pkiEzsigntemplatepublicID:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    fkiEzsignfoldertypeID:number 
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    sEzsignfoldertypeNameX:string 
    /**
     * The unique ID of the Userlogintype  Valid values:  |Value|Description|Detail| |-|-|-| |1|**Email Only**|The Ezsignsigner will receive a secure link by email| |2|**Email and phone or SMS**|The Ezsignsigner will receive a secure link by email and will need to authenticate using SMS or Phone call. **Additional fee applies**| |3|**Email and secret question**|The Ezsignsigner will receive a secure link by email and will need to authenticate using a predefined question and answer| |4|**In person only**|The Ezsignsigner will only be able to sign \"In-Person\" and there won\'t be any authentication. No email will be sent for invitation to sign. Make sure you evaluate the risk of signature denial and at minimum, we recommend you use a handwritten signature type| |5|**In person with phone or SMS**|The Ezsignsigner will only be able to sign \"In-Person\" and will need to authenticate using SMS or Phone call. No email will be sent for invitation to sign. **Additional fee applies**| |6|**Embedded**|The Ezsignsigner will only be able to sign in the embedded solution. No email will be sent for invitation to sign. **Additional fee applies**|   |7|**Embedded with phone or SMS**|The Ezsignsigner will only be able to sign in the embedded solution and will need to authenticate using SMS or Phone call. No email will be sent for invitation to sign. **Additional fee applies**|   |8|**No validation**|The Ezsignsigner will not receive an email and won\'t have to validate his connection using 2 factor. **Additional fee applies**|      |9|**Sms only**|The Ezsignsigner will not receive an email but will will need to authenticate using SMS. **Additional fee applies**|     
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    fkiUserlogintypeID:number 
    /**
     * The description of the Userlogintype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    sUserlogintypeDescriptionX:string 
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    fkiEzsigntemplateID?:number 
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    fkiEzsigntemplatepackageID?:number 
    /**
     * The description of the Ezsigntemplatepublic
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    sEzsigntemplatepublicDescription:string 
    /**
     * The referenceid of the Ezsigntemplatepublic
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    sEzsigntemplatepublicReferenceid:string 
    /**
     * Whether the ezsigntemplatepublic is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    bEzsigntemplatepublicIsactive:boolean 
    /**
     * The note of the Ezsigntemplatepublic
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    tEzsigntemplatepublicNote:string 
    /**
     * 
     * @type {FieldEEzsigntemplatepublicLimittype}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    eEzsigntemplatepublicLimittype:FieldEEzsigntemplatepublicLimittype 
    /**
     * The limit of the Ezsigntemplatepublic
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    iEzsigntemplatepublicLimit:number 
    /**
     * The limitexceeded of the Ezsigntemplatepublic
     * @type {number}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    iEzsigntemplatepublicLimitexceeded:number 
    /**
     * The limitexceededsince of the Ezsigntemplatepublic
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    dtEzsigntemplatepublicLimitexceededsince:string 
    /**
     * The url of the Ezsigntemplatepublic  You can add these value as query parameters to prefill the corresponding role  |Parameter|Description| |-|-| |sEzsigntemplatesignerDescription|The role to fill| |sContactFirstname|The contact firstname| |sContactLastname|The contact lastname| |sEmailAddress|The contact email| |sPhoneE164|The contact phone number| |sPhoneE164Cell|The contact cell phone number|
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    sEzsigntemplatepublicUrl:string 
    /**
     * The Ezsigntemplate/Ezsigntemplatepackage description
     * @type {string}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    sEzsigntemplatepublicEzsigntemplatedescription:string 
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    objAudit?:CommonAudit 
    /**
     * 
     * @type {Array<CustomEzsignfolderezsigntemplatepublicResponse>}
     * @memberof EzsigntemplatepublicResponseCompound
     */
    a_objEzsignfolderezsigntemplatepublic:Array<CustomEzsignfolderezsigntemplatepublicResponse> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzsigntemplatepublicResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicResponseCompound
 */
export class DataObjectEzsigntemplatepublicResponseCompound {
    pkiEzsigntemplatepublicID:number = 0
    fkiEzsignfoldertypeID:number = 0
    sEzsignfoldertypeNameX:string = ''
    fkiUserlogintypeID:number = 0
    sUserlogintypeDescriptionX:string = ''
    fkiEzsigntemplateID?:number = undefined
    fkiEzsigntemplatepackageID?:number = undefined
    sEzsigntemplatepublicDescription:string = ''
    sEzsigntemplatepublicReferenceid:string = ''
    bEzsigntemplatepublicIsactive:boolean = false
    tEzsigntemplatepublicNote:string = ''
    eEzsigntemplatepublicLimittype:FieldEEzsigntemplatepublicLimittype = 'Hour'
    iEzsigntemplatepublicLimit:number = 0
    iEzsigntemplatepublicLimitexceeded:number = 0
    dtEzsigntemplatepublicLimitexceededsince:string = ''
    sEzsigntemplatepublicUrl:string = ''
    sEzsigntemplatepublicEzsigntemplatedescription:string = ''
    objAudit?:CommonAudit = undefined
    a_objEzsignfolderezsigntemplatepublic:Array<CustomEzsignfolderezsigntemplatepublicResponse> = []
}

/**
 * @export 
 * A EzsigntemplatepublicResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatepublicResponseCompound
 */
export class ValidationObjectEzsigntemplatepublicResponseCompound {
   pkiEzsigntemplatepublicID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   fkiUserlogintypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sUserlogintypeDescriptionX = {
      type: 'string',
      required: true
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsigntemplatepublicDescription = {
      type: 'string',
      pattern: /^.{0,80}$/,
      required: true
   }
   sEzsigntemplatepublicReferenceid = {
      type: 'string',
      pattern: /^.{0,36}$/,
      required: true
   }
   bEzsigntemplatepublicIsactive = {
      type: 'boolean',
      required: true
   }
   tEzsigntemplatepublicNote = {
      type: 'string',
      pattern: /^.{0,65535}$/,
      required: true
   }
   eEzsigntemplatepublicLimittype = {
      type: 'enum',
      allowableValues: ['Hour','Day','Month','Total'],
      required: true
   }
   iEzsigntemplatepublicLimit = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   iEzsigntemplatepublicLimitexceeded = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   dtEzsigntemplatepublicLimitexceededsince = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   sEzsigntemplatepublicUrl = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: true
   }
   sEzsigntemplatepublicEzsigntemplatedescription = {
      type: 'string',
      pattern: /^.{1,80}$/,
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
   a_objEzsignfolderezsigntemplatepublic = {
      type: 'array',
      required: true
   }
} 


