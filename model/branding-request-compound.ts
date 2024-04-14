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
import { BrandingRequest } from './branding-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogo } from './field-ebranding-logo';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogointerface } from './field-ebranding-logointerface';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBrandingDescription } from './multilingual-branding-description';

/**
 * @type BrandingRequestCompound
 * A Branding Object and children
 * @export
 */
/*export type BrandingRequestCompound = BrandingRequest;*/
export interface BrandingRequestCompound {
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    pkiBrandingID?:number 
    /**
     * 
     * @type {MultilingualBrandingDescription}
     * @memberof BrandingRequestCompound
     */
    objBrandingDescription:MultilingualBrandingDescription 
    /**
     * 
     * @type {FieldEBrandingLogo}
     * @memberof BrandingRequestCompound
     */
    eBrandingLogo:FieldEBrandingLogo 
    /**
     * The Base64 encoded binary content of the branding logo. This need to match image type selected in eBrandingLogo if you supply an image. If you select \'Default\', the logo will be deleted and the default one will be used.
     * @type {string}
     * @memberof BrandingRequestCompound
     */
    sBrandingBase64?:string 
    /**
     * 
     * @type {FieldEBrandingLogointerface}
     * @memberof BrandingRequestCompound
     */
    eBrandingLogointerface?:FieldEBrandingLogointerface 
    /**
     * The Base64 encoded binary content of the branding logo. This need to match image type selected in eBrandingLogointerface if you supply an image. If you select \'Default\', the logo will be deleted and the default one will be used.
     * @type {string}
     * @memberof BrandingRequestCompound
     */
    sBrandingLogointerfaceBase64?:string 
    /**
     * The color of the text. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingColortext:number 
    /**
     * The color of the text in the link box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingColortextlinkbox:number 
    /**
     * The color of the text in the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingColortextbutton:number 
    /**
     * The color of the background. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingColorbackground:number 
    /**
     * The color of the background of the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingColorbackgroundbutton:number 
    /**
     * The color of the background of the small box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingColorbackgroundsmallbox:number 
    /**
     * The color of the interface. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingRequestCompound
     */
    iBrandingInterfacecolor?:number 
    /**
     * The name of the Branding  This value will only be set if you wish to overwrite the default name. If you want to keep the default name, leave this property empty
     * @type {string}
     * @memberof BrandingRequestCompound
     */
    sBrandingName?:string 
    /**
     * The email address.
     * @type {string}
     * @memberof BrandingRequestCompound
     */
    sEmailAddress?:string 
    /**
     * Whether the Branding is active or not
     * @type {boolean}
     * @memberof BrandingRequestCompound
     */
    bBrandingIsactive:boolean 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualBrandingDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualBrandingDescription } from './'

/**
 * @export 
 * A BrandingRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingRequestCompound
 */
export class DataObjectBrandingRequestCompound {
    pkiBrandingID?:number = undefined
    objBrandingDescription:MultilingualBrandingDescription = new DataObjectMultilingualBrandingDescription()
    eBrandingLogo:FieldEBrandingLogo = 'Default'
    sBrandingBase64?:string = undefined
    eBrandingLogointerface?:FieldEBrandingLogointerface = undefined
    sBrandingLogointerfaceBase64?:string = undefined
    iBrandingColortext:number = 0
    iBrandingColortextlinkbox:number = 0
    iBrandingColortextbutton:number = 0
    iBrandingColorbackground:number = 0
    iBrandingColorbackgroundbutton:number = 0
    iBrandingColorbackgroundsmallbox:number = 0
    iBrandingInterfacecolor?:number = undefined
    sBrandingName?:string = undefined
    sEmailAddress?:string = undefined
    bBrandingIsactive:boolean = false
}

/**
 * @export 
 * A BrandingRequestCompound Validation Object
 * @class ValidationObjectBrandingRequestCompound
 */
export class ValidationObjectBrandingRequestCompound {
   pkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objBrandingDescription = new ValidationObjectMultilingualBrandingDescription()
   eBrandingLogo = {
      type: 'enum',
      allowableValues: ['Default','JPEG','PNG'],
      required: true
   }
   sBrandingBase64 = {
      type: 'string',
      required: false
   }
   eBrandingLogointerface = {
      type: 'enum',
      allowableValues: ['Default','JPEG','PNG'],
      required: false
   }
   sBrandingLogointerfaceBase64 = {
      type: 'string',
      required: false
   }
   iBrandingColortext = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColortextlinkbox = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColortextbutton = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColorbackground = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColorbackgroundbutton = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingColorbackgroundsmallbox = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iBrandingInterfacecolor = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   sBrandingName = {
      type: 'string',
      pattern: '/^.{0,55}$/',
      required: false
   }
   sEmailAddress = {
      type: 'string',
      pattern: '/^[\w.%+\-!#$%&amp;&#39;*+\\/&#x3D;?^&#x60;{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/',
      required: false
   }
   bBrandingIsactive = {
      type: 'boolean',
      required: true
   }
} 


