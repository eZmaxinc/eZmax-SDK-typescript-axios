/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload } from './ezsignfolder-import-ezsigntemplatepackage-v1-response-mpayload';

import { DefaultObject } from '../base'

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
 * A EzsignfolderImportEzsigntemplatepackageV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderImportEzsigntemplatepackageV1ResponseAllOf
 */
export class DefaultObjectEzsignfolderImportEzsigntemplatepackageV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignfolderImportEzsigntemplatepackageV1ResponseMPayload> = {}
}


