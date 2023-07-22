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


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './ezsignfolder-import-ezsigntemplatepackage-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsignfolderImportEzsigntemplatepackageV1ResponseAllOf
 */
export interface EzsignfolderImportEzsigntemplatepackageV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload}
     * @memberof EzsignfolderImportEzsigntemplatepackageV1ResponseAllOf
     */
    'mPayload': EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseAllOf
 */
export class DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseAllOf {
   mPayload:EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload = new DataObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderImportEzsigntemplatepackageV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseAllOf
 */
export class ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseAllOf {
   mPayload = new ValidationObjectEzsignfolderImportEzsigntemplatepackageV1ResponseMPayload()
} 


