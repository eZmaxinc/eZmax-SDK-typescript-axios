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
import { BrandingResponse } from './branding-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEBrandingLogo } from './field-ebranding-logo';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualBrandingDescription } from './multilingual-branding-description';

/**
 * @type BrandingResponseCompound
 * A Branding Object
 * @export
 */
/** export type BrandingResponseCompound = BrandingResponse; */
export interface BrandingResponseCompound {
    /**
     * The unique ID of the Branding
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    pkiBrandingID:number 
    /**
     * The unique ID of the Email
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    fkiEmailID?:number 
    /**
     * 
     * @type {MultilingualBrandingDescription}
     * @memberof BrandingResponseCompound
     */
    objBrandingDescription:MultilingualBrandingDescription 
    /**
     * The Description of the Branding in the language of the requester
     * @type {string}
     * @memberof BrandingResponseCompound
     */
    sBrandingDescriptionX:string 
    /**
     * The name of the Branding  This value will only be set if you wish to overwrite the default name. If you want to keep the default name, leave this property empty
     * @type {string}
     * @memberof BrandingResponseCompound
     */
    sBrandingName?:string 
    /**
     * The email address.
     * @type {string}
     * @memberof BrandingResponseCompound
     */
    sEmailAddress?:string 
    /**
     * 
     * @type {FieldEBrandingLogo}
     * @memberof BrandingResponseCompound
     */
    eBrandingLogo:FieldEBrandingLogo 
    /**
     * The color of the text. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    iBrandingColortext:number 
    /**
     * The color of the text in the link box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    iBrandingColortextlinkbox:number 
    /**
     * The color of the text in the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    iBrandingColortextbutton:number 
    /**
     * The color of the background. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    iBrandingColorbackground:number 
    /**
     * The color of the background of the button. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    iBrandingColorbackgroundbutton:number 
    /**
     * The color of the background of the small box. This is a RGB color converted into integer
     * @type {number}
     * @memberof BrandingResponseCompound
     */
    iBrandingColorbackgroundsmallbox:number 
    /**
     * Whether the Branding is active or not
     * @type {boolean}
     * @memberof BrandingResponseCompound
     */
    bBrandingIsactive:boolean 
    /**
     * The url of the picture used as logo in the Branding
     * @type {string}
     * @memberof BrandingResponseCompound
     */
    sBrandingLogourl?:string 
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
 * A BrandingResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingResponseCompound
 */
export class DataObjectBrandingResponseCompound {
    pkiBrandingID:number = 0
    fkiEmailID?:number = undefined
    objBrandingDescription:MultilingualBrandingDescription = new DataObjectMultilingualBrandingDescription()
    sBrandingDescriptionX:string = ''
    sBrandingName?:string = undefined
    sEmailAddress?:string = undefined
    eBrandingLogo:FieldEBrandingLogo = 'Default'
    iBrandingColortext:number = 0
    iBrandingColortextlinkbox:number = 0
    iBrandingColortextbutton:number = 0
    iBrandingColorbackground:number = 0
    iBrandingColorbackgroundbutton:number = 0
    iBrandingColorbackgroundsmallbox:number = 0
    bBrandingIsactive:boolean = false
    sBrandingLogourl?:string = undefined
}

/**
 * @export 
 * A BrandingResponseCompound Validation Object
 * @class ValidationObjectBrandingResponseCompound
 */
export class ValidationObjectBrandingResponseCompound {
   pkiBrandingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEmailID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: false
   }
   objBrandingDescription = new ValidationObjectMultilingualBrandingDescription()
   sBrandingDescriptionX = {
      type: 'string',
      required: true
   }
   sBrandingName = {
      type: 'string',
      pattern: '/^.{0,55}$/',
      required: false
   }
   sEmailAddress = {
      type: 'string',
      required: false
   }
   eBrandingLogo = {
      type: 'enum',
      allowableValues: ['Default','JPEG','PNG'],
      required: true
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
   bBrandingIsactive = {
      type: 'boolean',
      required: true
   }
   sBrandingLogourl = {
      type: 'string',
      required: false
   }
} 


